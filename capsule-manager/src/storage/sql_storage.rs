// Copyright 2024 Ant Group Co., Ltd.
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

mod entities;

use super::storage_engine::StorageEngine;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::utils::jwt::jwa::{
    ContentEncryptionAlgorithm, EncryptionResult, Secret, SignatureAlgorithm,
};
use crate::utils::tool::{base64_decode, base64_encode};
use crate::{common::constants, errno, proto};
use entities::{
    data_key, data_meta,
    prelude::{DataKey, DataMeta, Rules},
    rules,
};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, Condition, EntityTrait, QueryFilter,
    TransactionTrait,
};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::collections::HashSet;
use std::ops::Deref;
use tonic::async_trait;

const SEPARATOR: &str = ",";

#[derive(Debug)]
pub struct SqlStoreEngine {
    db_conn: DatabaseConnection,
    seal_key: Vec<u8>,
}

pub struct SqlStoreEngineBuilder {
    db_url: String,
    max_connections: u32,
    password: Option<String>,
    seal_key: Vec<u8>,
}

impl SqlStoreEngineBuilder {
    pub fn new() -> Self {
        Self {
            db_url: "".to_string(),
            max_connections: 64,
            password: None,
            seal_key: vec![],
        }
    }

    pub fn db_url(mut self, db_url: &str) -> Self {
        self.db_url = db_url.to_string();
        self
    }

    pub fn seal_key(mut self, seal_key: &[u8]) -> Self {
        self.seal_key = seal_key.to_owned();
        self
    }

    pub fn max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub fn password(mut self, password: Option<&String>) -> Self {
        self.password = password.map(String::from);
        self
    }

    pub async fn build(&self) -> AuthResult<SqlStoreEngine> {
        let mut url = sqlx_core::Url::parse(&self.db_url)
            .map_err(|_| errno!(ErrorCode::InternalErr, "invalid db url {}", self.db_url))?;

        url.set_password(self.password.as_ref().map(Deref::deref))
            .map_err(|_| errno!(ErrorCode::InvalidArgument, "set password failed"))?;

        let mut opt: ConnectOptions = ConnectOptions::new(url);
        opt.max_connections(self.max_connections);

        let db_conn = Database::connect(opt).await?;

        Ok(SqlStoreEngine {
            db_conn,
            seal_key: self.seal_key.clone(),
        })
    }
}

impl data_meta::ActiveModel {
    pub fn compute_hmac(mut self, key: &[u8]) -> AuthResult<Self> {
        // prepare signing data
        let signing_data = [
            self.resource_uri.as_ref().as_str(),
            self.owner_party_id.as_ref().as_str(),
            if self.parents.is_not_set() {
                ""
            } else {
                self.parents.as_ref().as_deref().unwrap_or_default()
            },
        ]
        .join(constants::HASH_SEPARATOR);

        let secret = Secret::Bytes(key.to_vec());
        let signature = SignatureAlgorithm::HS256.sign(signing_data.as_bytes(), &secret)?;
        let sig_b64 = base64_encode(&signature);
        self.signature = ActiveValue::Set(sig_b64);
        Ok(self)
    }
}

impl data_meta::Model {
    pub fn verify_hmac(&self, key: &[u8]) -> AuthResult<()> {
        // prepare signing data
        let signing_data = [
            self.resource_uri.as_str(),
            self.owner_party_id.as_str(),
            self.parents.as_deref().unwrap_or_default(),
        ]
        .join(constants::HASH_SEPARATOR);
        let expected_signature = base64_decode(self.signature.as_str())?;
        let secret = Secret::Bytes(key.to_vec());
        SignatureAlgorithm::HS256
            .verify(&expected_signature, signing_data.as_bytes(), &secret)
            .map_err(|e| {
                errno!(
                    ErrorCode::DataIntegrityViolation,
                    "data_meta hmac verify failed {:?}.",
                    e
                )
            })?;
        Ok(())
    }
}

impl rules::ActiveModel {
    pub fn compute_hmac(mut self, key: &[u8]) -> AuthResult<Self> {
        // prepare signing data
        let signing_data = [
            self.rule_id.as_ref().as_str(),
            self.resource_uri.as_ref().as_str(),
            self.scope.as_ref().as_str(),
            self.grantee_party_ids.as_ref().as_str(),
            self.columns.as_ref().as_str(),
            if self.op_constrants.is_not_set() {
                ""
            } else {
                self.op_constrants.as_ref().as_deref().unwrap_or_default()
            },
            if self.global_constrants.is_not_set() {
                ""
            } else {
                self.global_constrants
                    .as_ref()
                    .as_deref()
                    .unwrap_or_default()
            },
        ]
        .join(constants::HASH_SEPARATOR);
        let secret = Secret::Bytes(key.to_vec());
        let signature = SignatureAlgorithm::HS256.sign(signing_data.as_bytes(), &secret)?;
        let sig_b64 = base64_encode(&signature);
        self.signature = ActiveValue::Set(sig_b64);
        Ok(self)
    }
}

impl rules::Model {
    pub fn verify_hmac(&self, key: &[u8]) -> AuthResult<()> {
        // prepare signing data
        let signing_data = [
            self.rule_id.as_str(),
            self.resource_uri.as_str(),
            self.scope.as_str(),
            self.grantee_party_ids.as_str(),
            self.columns.as_str(),
            self.op_constrants.as_deref().unwrap_or_default(),
            self.global_constrants.as_deref().unwrap_or_default(),
        ]
        .join(constants::HASH_SEPARATOR);
        let expected_signature = base64_decode(self.signature.as_str())?;
        let secret = Secret::Bytes(key.to_vec());
        SignatureAlgorithm::HS256
            .verify(&expected_signature, signing_data.as_bytes(), &secret)
            .map_err(|e| {
                errno!(
                    ErrorCode::DataIntegrityViolation,
                    "rules hmac verify failed {:?}.",
                    e
                )
            })?;
        Ok(())
    }
}

#[async_trait]
impl StorageEngine for SqlStoreEngine {
    async fn store_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        policy: &proto::Policy,
    ) -> AuthResult<()> {
        // First, create metadata if it does not exist,
        // and then register the corresponding data policy in the same transaction.
        let txn = self
            .db_conn
            .begin()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Init transcation failed: {:?}", e))?;

        match DataMeta::find_by_id(&policy.data_uuid)
            .one(&txn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?
        {
            Some(data_meta) => {
                data_meta.verify_hmac(&self.seal_key)?;
                // Make sure that the owner party ID matches the one specified in the request.
                if data_meta.owner_party_id != owner_party_id {
                    return Err(errno!(
                        ErrorCode::PermissionDenied,
                        "The owner party ID does not match the one specified in the request.",
                    )
                    .into());
                }
            }
            None => {
                data_meta::ActiveModel {
                    owner_party_id: ActiveValue::Set(owner_party_id.to_owned()),
                    resource_uri: ActiveValue::Set(policy.data_uuid.clone()),
                    ..Default::default()
                }
                .compute_hmac(&self.seal_key)?
                .insert(&txn)
                .await
                .map_err(|e| errno!(ErrorCode::InternalErr, "Insert data meta failed: {:?}", e))?;
            }
        }

        let mut active_rules: Vec<rules::ActiveModel> = vec![];
        for rule in policy.rules.iter() {
            active_rules.push(
                rules::ActiveModel {
                    rule_id: {
                        // If the rule_id is empty, generate a random UUID as the rule ID.
                        let id = if rule.rule_id.trim().is_empty() {
                            let new_uuid = uuid::Uuid::new_v4().to_string();
                            log::info!(target: "capsule_manager_log", "Generating rule_id, {}", new_uuid);
                            new_uuid
                        } else {
                            log::info!(target: "capsule_manager_log", "rule_id exist, {}", rule.rule_id.trim());
                            rule.rule_id.trim().to_owned()
                        };
                        ActiveValue::Set(id)
                    },
                    resource_uri: ActiveValue::Set(policy.data_uuid.clone()),
                    scope: ActiveValue::Set(scope.to_owned()),
                    grantee_party_ids: ActiveValue::Set(rule.grantee_party_ids.join(SEPARATOR)),
                    columns: ActiveValue::Set(rule.columns.join(SEPARATOR)),
                    op_constrants: ActiveValue::Set(Some(serde_json::to_string(
                        &rule.op_constraints,
                    )?)),
                    global_constrants: ActiveValue::Set(Some(serde_json::to_string(
                        &rule.global_constraints,
                    )?)),
                    ..Default::default()
                }
                .compute_hmac(&self.seal_key)?,
            );
        }

        Rules::insert_many(active_rules)
            .exec(&txn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Insert rules failed: {:?}", e))?;

        txn.commit()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Commit transcation failed: {:?}", e))?;

        Ok(())
    }

    async fn store_data_keys(
        &self,
        owner_party_id: &str,
        data_keys: &Vec<proto::DataKey>,
    ) -> AuthResult<()> {
        let txn = self
            .db_conn
            .begin()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Init transcation failed: {:?}", e))?;

        for data_key in data_keys.iter() {
            // First, create metadata if it does not exist,
            // and then register the corresponding data key in the same transaction.
            match DataMeta::find_by_id(&data_key.resource_uri)
                .one(&txn)
                .await
                .map_err(|e| errno!(ErrorCode::InternalErr, "Find data key failed: {:?}", e))?
            {
                Some(data_meta) => {
                    data_meta.verify_hmac(&self.seal_key)?;
                    // Make sure that the owner party ID matches the one specified in the request.
                    if data_meta.owner_party_id != owner_party_id {
                        return Err(errno!(
                            ErrorCode::PermissionDenied,
                            "The owner party ID {} does not match the resource {} in the request.",
                            owner_party_id,
                            data_key.resource_uri
                        )
                        .into());
                    }
                }
                None => {
                    DataMeta::insert(
                        data_meta::ActiveModel {
                            owner_party_id: ActiveValue::Set(owner_party_id.to_owned()),
                            resource_uri: ActiveValue::Set(data_key.resource_uri.clone()),
                            ..Default::default()
                        }
                        .compute_hmac(&self.seal_key)?,
                    )
                    .exec(&txn)
                    .await
                    .map_err(|e| {
                        errno!(
                            ErrorCode::InternalErr,
                            "Insert data meta {} failed: {:?}",
                            data_key.resource_uri,
                            e
                        )
                    })?;
                }
            }

            let encryption_options =
                ContentEncryptionAlgorithm::A128GCM.random_encryption_options()?;

            let result = ContentEncryptionAlgorithm::A128GCM.encrypt(
                data_key.data_key_b64.as_bytes(),
                "".as_bytes(),
                &self.seal_key,
                &encryption_options,
            )?;

            DataKey::insert(data_key::ActiveModel {
                resource_uri: ActiveValue::Set(data_key.resource_uri.clone()),
                encrypted_data_key: { ActiveValue::Set(base64_encode(&result.encrypted)) },
                iv: { ActiveValue::Set(base64_encode(&result.nonce)) },
                tag: { ActiveValue::Set(base64_encode(&result.tag)) },
                aad: { ActiveValue::Set(base64_encode(&result.additional_data)) },
                ..Default::default()
            })
            .exec(&txn)
            .await
            .map_err(|e| Error::from(e))?;
        }

        txn.commit()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Commit transcation failed: {:?}", e))?;

        Ok(())
    }

    async fn store_data_key(
        &self,
        resource_uri: &str,
        owner_party_id: &str,
        data_key: &str,
        ancestor_uuids: &Vec<String>,
    ) -> AuthResult<()> {
        let txn = self
            .db_conn
            .begin()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Init transcation failed: {:?}", e))?;

        // First, create metadata if it does not exist,
        // and then register the corresponding data key in the same transaction.
        match DataMeta::find_by_id(resource_uri)
            .one(&txn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?
        {
            Some(data_meta) => {
                data_meta.verify_hmac(&self.seal_key)?;
                // Make sure that the owner party ID matches the one specified in the request.
                if data_meta.owner_party_id != owner_party_id {
                    return Err(errno!(
                        ErrorCode::PermissionDenied,
                        "The owner party ID {} does not match the resource {} in the request.",
                        owner_party_id,
                        resource_uri
                    )
                    .into());
                }
            }
            None => {
                data_meta::ActiveModel {
                    owner_party_id: ActiveValue::Set(owner_party_id.to_owned()),
                    resource_uri: ActiveValue::Set(resource_uri.to_owned()),
                    parents: ActiveValue::Set(Some(ancestor_uuids.join(SEPARATOR))),
                    ..Default::default()
                }
                .compute_hmac(&self.seal_key)?
                .insert(&txn)
                .await
                .map_err(|e| {
                    errno!(
                        ErrorCode::InternalErr,
                        "Insert data meta {} failed: {:?}",
                        resource_uri,
                        e
                    )
                })?;
            }
        }

        let encryption_options = ContentEncryptionAlgorithm::A128GCM.random_encryption_options()?;

        let result = ContentEncryptionAlgorithm::A128GCM.encrypt(
            data_key.as_bytes(),
            "".as_bytes(),
            &self.seal_key,
            &encryption_options,
        )?;

        data_key::Entity::insert(data_key::ActiveModel {
            resource_uri: ActiveValue::Set(resource_uri.to_owned()),
            encrypted_data_key: { ActiveValue::Set(base64_encode(&result.encrypted)) },
            iv: { ActiveValue::Set(base64_encode(&result.nonce)) },
            tag: { ActiveValue::Set(base64_encode(&result.tag)) },
            aad: { ActiveValue::Set(base64_encode(&result.additional_data)) },
            ..Default::default()
        })
        .exec(&txn)
        .await
        .map_err(|e| Error::from(e))?;

        txn.commit()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Commit transcation failed: {:?}", e))?;

        Ok(())
    }

    async fn delete_data_key(&self, owner_party_id: &str, resource_uri: &str) -> AuthResult<()> {
        match DataMeta::find_by_id(resource_uri)
            .one(&self.db_conn)
            .await?
        {
            Some(data_meta) => {
                data_meta.verify_hmac(&self.seal_key)?;
                if data_meta.owner_party_id == owner_party_id {
                    data_key::Entity::delete_by_id(resource_uri)
                        .exec(&self.db_conn)
                        .await
                        .map_err(|e| {
                            errno!(ErrorCode::InternalErr, "delete data key failed: {:?}", e)
                        })?;
                } else {
                    return Err(errno!(
                        ErrorCode::PermissionDenied,
                        "The owner party ID {} does not match the resource {} in the request.",
                        owner_party_id,
                        resource_uri
                    )
                    .into());
                }
            }
            None => {
                return Err(errno!(
                    ErrorCode::NotFound,
                    "Data resource {} not found",
                    resource_uri
                )
                .into());
            }
        }
        Ok(())
    }

    async fn add_data_rule(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
        rule: &proto::Rule,
    ) -> AuthResult<()> {
        // First, create metadata if it does not exist,
        // and then register the corresponding data policy in the same transaction.
        let txn = self
            .db_conn
            .begin()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Init transcation failed: {:?}", e))?;

        match DataMeta::find_by_id(data_uuid).one(&txn).await? {
            Some(data_meta) => {
                data_meta.verify_hmac(&self.seal_key)?;
                // Make sure that the owner party ID matches the one specified in the request.
                if data_meta.owner_party_id != owner_party_id {
                    return Err(errno!(
                        ErrorCode::PermissionDenied,
                        "The owner party ID does not match the one specified in the request.",
                    )
                    .into());
                }
            }
            None => {
                data_meta::ActiveModel {
                    owner_party_id: ActiveValue::Set(owner_party_id.to_owned()),
                    resource_uri: ActiveValue::Set(data_uuid.to_owned()),
                    ..Default::default()
                }
                .compute_hmac(&self.seal_key)?
                .insert(&txn)
                .await
                .map_err(|e| errno!(ErrorCode::InternalErr, "Insert data meta failed: {:?}", e))?;
            }
        }

        rules::ActiveModel {
            rule_id: {
                // If the rule_id is empty, generate a random UUID as the rule ID.
                let id = if rule.rule_id.trim().is_empty() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    rule.rule_id.trim().to_owned()
                };
                ActiveValue::Set(id)
            },
            resource_uri: ActiveValue::Set(data_uuid.to_owned()),
            scope: ActiveValue::Set(scope.to_owned()),
            grantee_party_ids: ActiveValue::Set(rule.grantee_party_ids.join(SEPARATOR)),
            columns: ActiveValue::Set(rule.columns.join(SEPARATOR)),
            op_constrants: ActiveValue::Set(Some(serde_json::to_string(&rule.op_constraints)?)),
            global_constrants: ActiveValue::Set(Some(serde_json::to_string(
                &rule.global_constraints,
            )?)),
            ..Default::default()
        }
        .compute_hmac(&self.seal_key)?
        .insert(&txn)
        .await
        .map_err(|e| errno!(ErrorCode::InternalErr, "Insert rule failed: {:?}", e))?;

        txn.commit()
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Commit transcation failed: {:?}", e))?;

        Ok(())
    }

    async fn delete_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
    ) -> AuthResult<()> {
        match DataMeta::find_by_id(data_uuid)
            .one(&self.db_conn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?
        {
            Some(data_meta) => {
                data_meta.verify_hmac(&self.seal_key)?;
                if data_meta.owner_party_id == owner_party_id {
                    // Mark delete as true
                    Rules::update_many()
                        .col_expr(rules::Column::IsDeleted, Expr::value(true))
                        .filter(rules::Column::Scope.eq(scope))
                        .filter(rules::Column::ResourceUri.eq(data_uuid))
                        .exec(&self.db_conn)
                        .await
                        .map_err(|e| {
                            errno!(ErrorCode::InternalErr, "delete data policy failed: {:?}", e)
                        })?;
                } else {
                    return Err(errno!(
                        ErrorCode::PermissionDenied,
                        "The owner party ID {} does not match the resource {} in the request.",
                        owner_party_id,
                        data_uuid
                    )
                    .into());
                }
            }
            None => {
                return Err(
                    errno!(ErrorCode::NotFound, "Data resource {} not found", data_uuid).into(),
                );
            }
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
        match DataMeta::find_by_id(data_uuid)
            .one(&self.db_conn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?
        {
            Some(data_meta) => {
                data_meta.verify_hmac(&self.seal_key)?;
                if data_meta.owner_party_id == owner_party_id {
                    // Mark delete as true
                    Rules::update_many()
                        .col_expr(rules::Column::IsDeleted, Expr::value(true))
                        .filter(rules::Column::Scope.eq(scope))
                        .filter(rules::Column::ResourceUri.eq(data_uuid))
                        .filter(rules::Column::RuleId.eq(rule_id))
                        .exec(&self.db_conn)
                        .await
                        .map_err(|e| {
                            errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e)
                        })?;
                } else {
                    return Err(errno!(
                        ErrorCode::PermissionDenied,
                        "The owner party ID {} does not match the resource {} in the request.",
                        owner_party_id,
                        data_uuid
                    )
                    .into());
                }
            }
            None => {
                return Err(
                    errno!(ErrorCode::NotFound, "Data resource {} not found", data_uuid).into(),
                );
            }
        }
        Ok(())
    }

    async fn store_public_key(&self, _owner_party_id: &str, _public_key: &str) -> AuthResult<()> {
        todo!()
    }

    async fn get_data_keys(&self, resource_uris: &Vec<&str>) -> AuthResult<Vec<proto::DataKey>> {
        let cond = resource_uris.iter().fold(Condition::any(), |cond, &x| {
            cond.add(data_key::Column::ResourceUri.eq(x))
        });
        let encrypted_data_keys = data_key::Entity::find()
            .filter(cond)
            .all(&self.db_conn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?;

        let mut data_keys = vec![];
        for encrypted_data_key in encrypted_data_keys.iter() {
            data_keys.push(proto::DataKey {
                resource_uri: encrypted_data_key.resource_uri.clone(),
                data_key_b64: {
                    let result = EncryptionResult {
                        nonce: base64_decode(&encrypted_data_key.iv)?,
                        encrypted: base64_decode(&encrypted_data_key.encrypted_data_key)?,
                        tag: base64_decode(&encrypted_data_key.tag)?,
                        additional_data: base64_decode(&encrypted_data_key.aad)?,
                    };
                    let data_key =
                        ContentEncryptionAlgorithm::A128GCM.decrypt(&result, &self.seal_key)?;
                    std::str::from_utf8(&data_key)?.to_owned()
                },
            });
        }
        Ok(data_keys)
    }

    async fn get_data_party(&self, resource_uri: &str) -> AuthResult<String> {
        match DataMeta::find_by_id(resource_uri)
            .one(&self.db_conn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?
        {
            Some(data_meta) => {
                data_meta.verify_hmac(&self.seal_key)?;
                Ok(data_meta.owner_party_id.clone())
            }
            None => {
                return Err(errno!(
                    ErrorCode::NotFound,
                    "Data resource {} not found",
                    resource_uri
                )
                .into());
            }
        }
    }

    async fn get_data_policys(
        &self,
        owner_party_id: &str,
        scope: &str,
    ) -> AuthResult<Vec<proto::Policy>> {
        let data_meta_with_rules = DataMeta::find()
            .find_with_related(Rules)
            .filter(rules::Column::Scope.eq(scope))
            .filter(data_meta::Column::OwnerPartyId.eq(owner_party_id))
            .filter(rules::Column::IsDeleted.eq(false))
            .all(&self.db_conn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?;

        let mut policies: Vec<proto::Policy> = vec![];

        for (data_meta, rules) in data_meta_with_rules.iter() {
            data_meta.verify_hmac(&self.seal_key)?;
            let mut policy = proto::Policy {
                data_uuid: data_meta.resource_uri.clone(),
                rules: vec![],
            };

            for rule in rules.iter() {
                rule.verify_hmac(&self.seal_key)?;
                policy.rules.push(proto::Rule {
                    rule_id: rule.rule_id.clone(),
                    grantee_party_ids: rule
                        .grantee_party_ids
                        .split(SEPARATOR)
                        .map(|s| s.to_string())
                        .collect(),
                    op_constraints: serde_json::from_str(match rule.op_constrants {
                        Some(ref s) => s.as_ref(),
                        None => "[]",
                    })?,
                    columns: rule
                        .columns
                        .split(SEPARATOR)
                        .map(|s| s.to_string())
                        .collect(),
                    global_constraints: serde_json::from_str(match rule.global_constrants {
                        Some(ref s) => s.as_ref(),
                        None => "[]",
                    })?,
                });
            }

            policies.push(policy);
        }

        Ok(policies)
    }

    async fn get_data_policy_by_id(
        &self,
        data_uuid: &str,
        scope: &str,
    ) -> AuthResult<proto::Policy> {
        let rules = Rules::find()
            .filter(rules::Column::ResourceUri.eq(data_uuid))
            .filter(rules::Column::Scope.eq(scope))
            .filter(rules::Column::IsDeleted.eq(false))
            .all(&self.db_conn)
            .await
            .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?;

        let mut policy = proto::Policy {
            data_uuid: data_uuid.to_owned(),
            rules: vec![],
        };

        for rule in rules.iter() {
            rule.verify_hmac(&self.seal_key)?;
            policy.rules.push(proto::Rule {
                rule_id: rule.rule_id.clone(),
                grantee_party_ids: rule
                    .grantee_party_ids
                    .split(SEPARATOR)
                    .map(|s| s.to_string())
                    .collect(),
                op_constraints: serde_json::from_str(match rule.op_constrants {
                    Some(ref s) => s.as_ref(),
                    None => "[]",
                })?,
                columns: rule
                    .columns
                    .split(SEPARATOR)
                    .map(|s| s.to_string())
                    .collect(),
                global_constraints: serde_json::from_str(match rule.global_constrants {
                    Some(ref s) => s.as_ref(),
                    None => "[]",
                })?,
            });
        }
        Ok(policy)
    }

    async fn get_policy_party_by_id(&self, data_uuid: &str, _scope: &str) -> AuthResult<String> {
        self.get_data_party(data_uuid).await
    }

    async fn get_public_key(&self, _owner_party_id: &str) -> AuthResult<String> {
        todo!()
    }

    async fn get_original_parties(&self, data_uuid: &str) -> AuthResult<Vec<String>> {
        self.search_original_parties(data_uuid).await
    }
}

impl SqlStoreEngine {
    async fn search_original_parties(&self, data_uuid: &str) -> AuthResult<Vec<String>> {
        let mut q = std::collections::VecDeque::new();
        let mut visited = HashSet::new();
        let mut result = HashSet::new();
        q.push_back(data_uuid.to_owned());
        while !q.is_empty() {
            let data_uuid = q.pop_front().unwrap();
            visited.insert(data_uuid.clone());
            match DataMeta::find_by_id(&data_uuid)
                .one(&self.db_conn)
                .await
                .map_err(|e| errno!(ErrorCode::InternalErr, "Find meta data failed: {:?}", e))?
            {
                Some(data_meta) => {
                    data_meta.verify_hmac(&self.seal_key)?;
                    match data_meta.parents {
                        Some(parents) => {
                            for parent in parents.split(SEPARATOR) {
                                if !visited.contains(parent) {
                                    q.push_back(parent.to_owned())
                                }
                            }
                        }
                        None => {
                            result.insert(data_meta.owner_party_id.clone());
                        }
                    }
                }
                None => {
                    return Err(errno!(
                        ErrorCode::NotFound,
                        "Data resource {} not found",
                        data_uuid
                    ))
                }
            }
        }
        Ok(result.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        proto,
        storage::{sql_storage::SqlStoreEngineBuilder, storage_engine::StorageEngine},
    };

    #[tokio::test]
    async fn test_store_policy() {
        // let seal_key = [
        //     35, 190, 11, 127, 16, 255, 250, 117, 106, 176, 0, 158, 143, 147, 255, 186,
        // ];
        // let sql_engine = SqlStoreEngineBuilder::new()
        //     .db_url("mysql://root@localhost:3306/capsulemanager")
        //     .seal_key(&seal_key)
        //     .build()
        //     .await
        //     .unwrap();

        // let policy_json_str = r#"
        // {
        //         "data_uuid":"data_uuid",
        //         "rules":[
        //             {
        //                 "rule_id":"rule_id1",
        //                 "grantee_party_ids":[
        //                     "FUWS2LJNIJCUOSKOEBJFGQJAKBKUETCJIMQEWRKZFUWS2LJNBJGQ"
        //                 ],
        //                 "op_constraints":[
        //                     {
        //                         "op_name":"OP_PSI"
        //                     }
        //                 ],
        //                 "columns":[
        //                     "col"
        //                 ]
        //             },
        //             {
        //                 "rule_id":"rule_id2",
        //                 "grantee_party_ids":[
        //                     "FUWS2LJNIJCUOSKOEBJFGQJAKBKUETCJIMQEWRKZFUWS2LJNBJGQ"
        //                 ],
        //                 "op_constraints":[
        //                     {
        //                         "op_name":"OP_XGB"
        //                     }
        //                 ],
        //                 "columns":[
        //                     "col2"
        //                 ]
        //             }
        //         ]
        //     }
        // "#;

        // let policy: proto::Policy = serde_json::from_str(policy_json_str).unwrap();
        // sql_engine
        //     .store_data_policy("owner_id", "default", &policy)
        //     .await
        //     .unwrap();
    }

    #[tokio::test]
    async fn test_get_original_parties() {
        // let seal_key = [
        //     35, 190, 11, 127, 16, 255, 250, 117, 106, 176, 0, 158, 143, 147, 255, 186,
        // ];
        // let sql_engine = SqlStoreEngineBuilder::new()
        //     .db_url("mysql://root@localhost:3306/capsulemanager")
        //     .seal_key(&seal_key)
        //     .build()
        //     .await
        //     .unwrap();

        // sql_engine
        //     .store_data_keys(
        //         "party1",
        //         &vec![DataKey {
        //             resource_uri: "A".to_owned(),
        //             data_key_b64: "keyA".to_owned(),
        //         }],
        //     )
        //     .await
        //     .unwrap();

        // sql_engine
        //     .store_data_keys(
        //         "party2",
        //         &vec![DataKey {
        //             resource_uri: "B".to_owned(),
        //             data_key_b64: "keyB".to_owned(),
        //         }],
        //     )
        //     .await
        //     .unwrap();

        // let data_keys = sql_engine.get_data_keys(&vec!["A", "B"]).await.unwrap();
        // assert_eq!(data_keys.len(), 2);

        // sql_engine
        //     .store_data_key("C", "TEE", "key", &vec!["A".to_owned(), "B".to_owned()])
        //     .await
        //     .unwrap();

        // let parties = sql_engine.get_original_parties("C").await.unwrap();

        // assert_eq!(parties.len(), 2);
    }

    #[tokio::test]
    async fn test_get_data_keys() {
        // let seal_key = [
        //     35, 190, 11, 127, 16, 255, 250, 117, 106, 176, 0, 158, 143, 147, 255, 186,
        // ];
        // let sql_engine = SqlStoreEngineBuilder::new()
        //     .db_url("mysql://root@localhost:3306/capsulemanager")
        //     .seal_key(&seal_key)
        //     .build()
        //     .await
        //     .unwrap();

        // sql_engine
        //     .store_data_keys(
        //         "party1",
        //         &vec![DataKey {
        //             resource_uri: "A".to_owned(),
        //             data_key_b64: "keyA".to_owned(),
        //         }],
        //     )
        //     .await
        //     .unwrap();

        // sql_engine
        //     .store_data_keys(
        //         "party2",
        //         &vec![DataKey {
        //             resource_uri: "B".to_owned(),
        //             data_key_b64: "keyB".to_owned(),
        //         }],
        //     )
        //     .await
        //     .unwrap();

        // let data_keys = sql_engine.get_data_keys(&vec!["A", "B"]).await.unwrap();
        // assert_eq!(data_keys.len(), 2);

        // sql_engine
        //     .store_data_key("C", "TEE", "key", &vec!["A".to_owned(), "B".to_owned()])
        //     .await
        //     .unwrap();

        // let parties = sql_engine.get_original_parties("C").await.unwrap();

        // assert_eq!(parties.len(), 2);
    }
}
