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

use super::storage_engine::StorageEngine;
use crate::core::model;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::{cm_assert, errno, return_errno};
use capsule_manager_tonic::secretflowapis::v2::sdc::capsule_manager::*;
use log::warn;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tonic::async_trait;

#[derive(Debug)]
struct DataMeta {
    // All data keys under the data uuid
    // resource_uri -> data_key
    data_keys: HashMap<String, String>,

    // owner party id
    party_id: String,

    // Record the data from which the data uuid is directly derived
    parents: Vec<String>,
}

#[derive(Debug)]
struct PolicyMeta {
    // data policy
    policy: Policy,
    // policy party_id
    party_id: String,
    // policy scope
    scope: String,
}

// inmemory storage implementation
#[derive(Debug)]
pub struct InMemoryStorage {
    // key: scope/data_uuid
    data_policy_map: Arc<Mutex<HashMap<String, PolicyMeta>>>,
    // key: data_uuid
    data_keys_map: Arc<Mutex<HashMap<String, DataMeta>>>,
    // key: party_id
    public_key_map: Arc<Mutex<HashMap<String, String>>>,
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        let data_policy_map = Arc::new(Mutex::new(HashMap::new()));
        let data_keys_map = Arc::new(Mutex::new(HashMap::new()));
        let public_key_map = Arc::new(Mutex::new(HashMap::new()));
        Self {
            data_policy_map,
            data_keys_map,
            public_key_map,
        }
    }
}

fn dfs<'a>(
    data_uuid: &'a String,
    data_keys_map: &'a HashMap<String, DataMeta>,
    result: &mut HashSet<String>,
    visited: &mut HashSet<&'a String>,
) -> AuthResult<()> {
    let data_meta = data_keys_map.get(data_uuid).ok_or(errno!(
        ErrorCode::NotFound,
        "data_uuid {} has be not stored",
        data_uuid
    ))?;
    if visited.contains(data_uuid) {
        return Ok(());
    }
    visited.insert(data_uuid);
    if data_meta.parents.is_empty() {
        result.insert(data_meta.party_id.clone());
    }
    for parent_data_uuid in data_meta.parents.iter() {
        dfs(parent_data_uuid, data_keys_map, result, visited)?;
    }
    Ok(())
}

#[async_trait]
impl StorageEngine for InMemoryStorage {
    async fn store_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        policy: &Policy,
    ) -> AuthResult<()> {
        let data_uuid = &policy.data_uuid;
        let key = format!("{}/{}", scope, data_uuid);
        // if lock crash, the program will terminate
        let mut data_policy_map = self.data_policy_map.lock().unwrap();
        data_policy_map.contains_key(&key).then(|| {
            warn!(
                "data_uuid {} scope {} has policy, will be overwrite",
                data_uuid, scope
            )
        });
        data_policy_map.insert(
            key,
            PolicyMeta {
                policy: policy.clone(),
                party_id: owner_party_id.to_string(),
                scope: scope.to_string(),
            },
        );
        Ok(())
    }

    async fn store_data_keys(
        &self,
        owner_party_id: &str,
        data_keys: &Vec<DataKey>,
    ) -> AuthResult<()> {
        // if lock crash, the program will terminate
        let mut data_keys_map = self.data_keys_map.lock().unwrap();
        // judge whether data_key has ready existed in data_key vector
        for data_key in data_keys.iter() {
            let resource_uri_inner: model::ResourceUri = data_key.resource_uri.parse()?;
            if let Some(data_meta) = data_keys_map.get_mut(&resource_uri_inner.data_uuid) {
                cm_assert!(
                    data_meta.party_id == owner_party_id,
                    "party_id {} is wrong",
                    owner_party_id
                );
                data_meta
                    .data_keys
                    .contains_key(&data_key.resource_uri)
                    .then(|| {
                        warn!(
                            "resource_uri {} data_key will be overwrite",
                            &data_key.resource_uri
                        );
                    });
                data_meta.data_keys.insert(
                    data_key.resource_uri.to_string(),
                    data_key.data_key_b64.clone(),
                );

                data_meta.party_id = owner_party_id.to_string();
            } else {
                let mut data_keys = HashMap::new();
                data_keys.insert(
                    data_key.resource_uri.to_string(),
                    data_key.data_key_b64.clone(),
                );

                data_keys_map.insert(
                    resource_uri_inner.data_uuid,
                    DataMeta {
                        data_keys,
                        party_id: owner_party_id.to_string(),
                        parents: vec![],
                    },
                );
            }
        }
        Ok(())
    }

    async fn store_data_key(
        &self,
        resource_uri: &str,
        owner_party_id: &str,
        data_key: &str,
        ancestor_uuids: &Vec<String>,
    ) -> AuthResult<()> {
        // if lock crash, the program will terminate
        let mut data_keys_map = self.data_keys_map.lock().unwrap();
        let resource_uri_inner: model::ResourceUri = resource_uri.parse()?;
        if let Some(data_meta) = data_keys_map.get_mut(&resource_uri_inner.data_uuid) {
            cm_assert!(
                data_meta.party_id == owner_party_id,
                "party_id {} is wrong",
                owner_party_id
            );
            data_meta
                .data_keys
                .insert(resource_uri.to_string(), data_key.to_string());

            data_meta.party_id = owner_party_id.to_string();

            data_meta.parents.append(&mut ancestor_uuids.clone());
            data_meta.parents.sort();
            data_meta.parents.dedup();
        } else {
            let mut data_keys = HashMap::new();
            data_keys.insert(resource_uri.to_string(), data_key.to_string());

            data_keys_map.insert(
                resource_uri_inner.data_uuid,
                DataMeta {
                    data_keys,
                    party_id: owner_party_id.to_string(),
                    parents: ancestor_uuids.clone(),
                },
            );
        }
        Ok(())
    }

    async fn delete_data_key(&self, owner_party_id: &str, resource_uri: &str) -> AuthResult<()> {
        let mut data_keys_map = self.data_keys_map.lock().unwrap();
        let resource_uri_inner: model::ResourceUri = resource_uri.parse()?;
        if let Some(data_meta) = data_keys_map.get_mut(&resource_uri_inner.data_uuid) {
            cm_assert!(
                data_meta.party_id == owner_party_id,
                "party_id {} is wrong",
                owner_party_id,
            );
            data_meta.data_keys.remove(resource_uri);
        }
        Ok(())
    }

    async fn add_data_rule(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
        rule: &Rule,
    ) -> AuthResult<()> {
        let key = format!("{}/{}", scope, data_uuid);
        // if lock crash, the program will terminate
        let mut data_policy_map = self.data_policy_map.lock().unwrap();
        if !data_policy_map.contains_key(&key) {
            data_policy_map.insert(
                key,
                PolicyMeta {
                    policy: Policy {
                        data_uuid: data_uuid.to_string(),
                        rules: vec![rule.clone()],
                    },
                    scope: scope.to_string(),
                    party_id: owner_party_id.to_string(),
                },
            );
        } else {
            let policy_meta = data_policy_map
                .get_mut(&key)
                .ok_or(errno!(ErrorCode::NotFound, "data policy is empty."))?;
            cm_assert!(policy_meta.party_id == owner_party_id, "party_id is wrong");
            cm_assert!(
                policy_meta.policy.data_uuid == data_uuid,
                "data_uuid is wrong"
            );
            policy_meta.policy.rules.push(rule.clone());
        }
        Ok(())
    }

    async fn delete_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
    ) -> AuthResult<()> {
        let key = format!("{}/{}", scope, data_uuid);
        // if lock crash, the program will terminate
        let mut data_policy_map = self.data_policy_map.lock().unwrap();
        // judge whether data_policy has existed
        if !data_policy_map.contains_key(&key) {
            warn!(
                "party_id {} scope {} policy has not stored.",
                owner_party_id, scope
            );
        } else {
            let policy_meta = data_policy_map
                .get_mut(&key)
                .ok_or(errno!(ErrorCode::NotFound, "data policy is empty."))?;
            cm_assert!(policy_meta.party_id == owner_party_id, "party_id is wrong");
            cm_assert!(
                policy_meta.policy.data_uuid == data_uuid,
                "data_uuid is wrong"
            );
            data_policy_map.remove(&key);
        }
        Ok(())
    }

    async fn delete_data_rule(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
        rule_id: &str,
    ) -> AuthResult<()> {
        let key = format!("{}/{}", scope, data_uuid);
        // if lock crash, the program will terminate
        let mut data_policy_map = self.data_policy_map.lock().unwrap();
        // judge whether data_policy has existed
        if !data_policy_map.contains_key(&key) {
            warn!(
                "party_id {} scope {} policy has not stored.",
                owner_party_id, scope
            );
        } else {
            let policy_meta = data_policy_map
                .get_mut(&key)
                .ok_or(errno!(ErrorCode::NotFound, "data policy is empty."))?;
            cm_assert!(policy_meta.party_id == owner_party_id, "party_id is wrong");
            cm_assert!(
                policy_meta.policy.data_uuid == data_uuid,
                "data_uuid is wrong"
            );
            policy_meta
                .policy
                .rules
                .retain_mut(|x| x.rule_id != rule_id);
        }
        Ok(())
    }

    async fn store_public_key(&self, owner_party_id: &str, public_key: &str) -> AuthResult<()> {
        // if lock crash, the program will terminate
        let mut public_key_map = self.public_key_map.lock().unwrap();
        (!public_key_map.contains_key(owner_party_id))
            .then(|| 0)
            .ok_or(errno!(
                ErrorCode::AlreadyExists,
                "party_id {} public_key has stored.",
                owner_party_id
            ))?;
        public_key_map.insert(owner_party_id.to_string(), public_key.to_string());
        Ok(())
    }

    async fn get_data_keys(&self, resource_uris: &Vec<&str>) -> AuthResult<Vec<DataKey>> {
        // if lock crash, the program will terminate
        let data_keys_map = self.data_keys_map.lock().unwrap();
        // collect data keys
        let mut result = vec![];
        for resource_uri in resource_uris.iter() {
            let resource_uri_inner: model::ResourceUri = resource_uri.parse()?;
            if let Some(data_meta) = data_keys_map.get(&resource_uri_inner.data_uuid) {
                if let Some(data_key_b64) = data_meta.data_keys.get(*resource_uri) {
                    result.push(DataKey {
                        resource_uri: resource_uri.to_string(),
                        data_key_b64: data_key_b64.clone(),
                    });
                }
            }
        }
        if result.is_empty() {
            return_errno!(ErrorCode::NotFound, "data_keys not found.");
        }
        Ok(result)
    }

    async fn get_data_party(&self, resource_uri: &str) -> AuthResult<String> {
        // if lock crash, the program will terminate
        let data_keys_map = self.data_keys_map.lock().unwrap();
        // get data party id
        let data_meta = data_keys_map
            .get(resource_uri)
            .ok_or(errno!(ErrorCode::NotFound, "party id is not existed"))?;
        Ok(data_meta.party_id.clone())
    }

    async fn get_data_policys(&self, owner_party_id: &str, scope: &str) -> AuthResult<Vec<Policy>> {
        // if lock crash, the program will terminate
        let data_policy_map = self.data_policy_map.lock().unwrap();
        let mut policy_vec = vec![];
        for (_, policy_meta) in data_policy_map.iter() {
            if policy_meta.scope == scope && policy_meta.party_id == owner_party_id {
                policy_vec.push(policy_meta.policy.clone());
            }
        }
        Ok(policy_vec)
    }

    async fn get_data_policy_by_id(&self, data_uuid: &str, scope: &str) -> AuthResult<Policy> {
        let key = format!("{}/{}", scope, data_uuid);
        // if lock crash, the program will terminate
        let data_policy_map = self.data_policy_map.lock().unwrap();
        let policy_meta = data_policy_map
            .get(&key)
            .ok_or(errno!(ErrorCode::NotFound, "data policy is empty."))?;
        Ok(policy_meta.policy.clone())
    }

    async fn get_policy_party_by_id(&self, data_uuid: &str, scope: &str) -> AuthResult<String> {
        let key = format!("{}/{}", scope, data_uuid);
        // if lock crash, the program will terminate
        let data_policy_map = self.data_policy_map.lock().unwrap();
        let policy_meta = data_policy_map
            .get(&key)
            .ok_or(errno!(ErrorCode::NotFound, "data policy is empty."))?;
        Ok(policy_meta.party_id.clone())
    }

    async fn get_public_key(&self, owner_party_id: &str) -> AuthResult<String> {
        // if lock crash, the program will terminate
        let public_key_map = self.public_key_map.lock().unwrap();
        if let Some(public_key) = public_key_map.get(owner_party_id) {
            return Ok(public_key.clone());
        } else {
            return_errno!(
                ErrorCode::NotFound,
                "party_id {} public_key has not stored.",
                owner_party_id
            );
        }
    }

    async fn get_original_parties(&self, data_uuid: &str) -> AuthResult<Vec<String>> {
        let mut visited: HashSet<&String> = HashSet::new();
        let mut result: HashSet<String> = HashSet::new();
        // if lock crash, the program will terminate
        let data_keys_map = self.data_keys_map.lock().unwrap();
        dfs(
            &data_uuid.to_string(),
            &data_keys_map,
            &mut result,
            &mut visited,
        )?;
        Ok(result.into_iter().collect())
    }
}

impl InMemoryStorage {
    pub fn new() -> Self {
        let data_policy_map = Arc::new(Mutex::new(HashMap::new()));
        let data_keys_map = Arc::new(Mutex::new(HashMap::new()));
        let public_key_map = Arc::new(Mutex::new(HashMap::new()));
        Self {
            data_policy_map,
            data_keys_map,
            public_key_map,
        }
    }
}
