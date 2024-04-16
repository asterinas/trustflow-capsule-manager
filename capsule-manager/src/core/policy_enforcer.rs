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


use crate::core::model::policy::{self, Rule};
use crate::core::model::request;
use crate::errno;
use crate::error::errors::{Error, ErrorCode, ErrorLocation};

use log::warn;
use rhai::{Engine, Scope};

#[derive(Debug)]
pub struct PolicyEnforcer {
    engine: Engine,
}

impl PolicyEnforcer {
    pub fn new() -> PolicyEnforcer {
        PolicyEnforcer {
            engine: Engine::new_raw(),
        }
    }
}

impl PolicyEnforcer {
    pub fn enforce(
        &self,
        request: &request::SingleResourceRequest,
        policy: &policy::Policy,
    ) -> Result<(), Error> {
        for rule in policy.rules_iter() {
            match self.match_rule(request, rule) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    warn!("rule {} match failed: {:?}.", rule.get_role_id(), e);
                }
            }
        }

        Err(errno!(
            ErrorCode::PermissionDenied,
            "request is not satisfied with the policy {}.",
            policy.get_data_uuid()
        ))
    }

    fn match_rule(
        &self,
        request: &request::SingleResourceRequest,
        rule: &Rule,
    ) -> Result<(), Error> {
        // initiator party should be in the list of grantee_party_id
        if !rule.has_grantee_party(&request.global_attributes.initiator_party_id) {
            return Err(errno!(
                ErrorCode::PermissionDenied,
                "initiator party {} is not authorized in this rule {}.",
                request.global_attributes.initiator_party_id,
                rule.get_role_id()
            ));
        }

        let op = &request.global_attributes.op_name;
        // If there is no allowance for arbitrary operations to be executed in the
        // rules, and the operation to be executed is not in the authorized
        // operation list, it indicates that the request does not comply with
        // that rule.
        if !rule.enable_any_op() && !rule.has_operator(op) {
            return Err(errno!(
                ErrorCode::PermissionDenied,
                "operator {:?} is not authorized in this rule {}.",
                op,
                rule.get_role_id()
            ));
        }

        if !rule.enable_any_columns() && !rule.contain_columns(request.columns) {
            return Err(errno!(
                ErrorCode::PermissionDenied,
                "columns {:?} is not authorized in this rule {}.",
                request.columns,
                rule.get_role_id()
            ));
        }

        // Flatten the request to json format
        let r_json = request.to_json_string()?;
        // Parse the json string
        let r = self
            .engine
            .parse_json(&r_json, false)
            .map_err(|e| errno!(ErrorCode::InvalidArgument, "parse json failed, {:?}", e))?;
        let mut scope = Scope::new();
        scope.push("r", r);

        // Then verify op-specific constraints
        let constraints = rule.get_op_constraints(op);
        // evaluate constraints on the request
        for (i, &constraint) in constraints.iter().enumerate() {
            let ast_compiled = self.engine.compile_expression(constraint).map_err(|_e| {
                errno!(
                    ErrorCode::InvalidArgument,
                    "parse {}th op-specific constraint failed.",
                    i
                )
            })?;

            let result = self
                .engine
                .eval_ast_with_scope::<bool>(&mut scope, &ast_compiled)
                .map_err(|e| {
                    errno!(
                        ErrorCode::PermissionDenied,
                        "request is not satisfied with the {}th op-specific constraint, error: {:?}.",
                        i, e
                    )
                })?;

            if !result {
                return Err(errno!(
                    ErrorCode::PermissionDenied,
                    "request is not satisfied with the {}th op-specific constraint.",
                    i
                ));
            }
        }

        // verify the global constraints
        for (i, constraint) in rule.global_constraints_iter() {
            let ast_compiled = self.engine.compile_expression(constraint).map_err(|_e| {
                errno!(
                    ErrorCode::InvalidArgument,
                    "parse {}th op-specific constraint failed.",
                    i
                )
            })?;

            let result = self
                .engine
                .eval_ast_with_scope::<bool>(&mut scope, &ast_compiled)
                .map_err(|e| {
                    errno!(
                        ErrorCode::PermissionDenied,
                        "request is not satisfied with the {}th op-specific constraint, error: {:?}.",
                        i, e
                    )
                })?;

            if !result {
                return Err(errno!(
                    ErrorCode::PermissionDenied,
                    "request is not satisfied with the {}th op-specific constraint.",
                    i
                ));
            }
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use crate::core::model::policy::Policy;
    use crate::core::model::request::{
        Environment, GlobalAttributes, SingleResourceRequest, TeeIdentity, TeeInfo,
    };

    use super::PolicyEnforcer;

    #[test]
    fn serialization_round_trip() {
        let attrs = r#"
        {
            "xgb": {
                "tree_num": 1
            }
        }"#;

        let global_attrs = GlobalAttributes {
            initiator_party_id: "partyid#1".to_owned(),
            scope: "workspace#1".to_owned(),
            op_name: crate::core::model::Operator::PSI,
            env: Some(Environment {
                request_time: Some("2023-08-24T12:55:52Z".parse::<DateTime<Utc>>().unwrap()),
                tee: Some(TeeInfo {
                    platform: crate::core::model::request::TeePlatform::SGX,
                    identity: Some(TeeIdentity::SGX {
                        mr_enclave: "mr_enclave".to_owned(),
                        mr_signer: "mr_signer".to_owned(),
                    }),
                }),
            }),
            custom_attrs: Some(serde_json::from_str(attrs).unwrap()),
        };
        let resource_uri = String::from("data1");
        let columns = vec!["fields1".to_owned()];
        let request = SingleResourceRequest {
            resource_uri: &resource_uri,
            columns: &columns,
            custom_attrs: None,
            global_attributes: &global_attrs,
        };

        let enforcer = PolicyEnforcer::new();
        let policy_str = r#"
        {
                "data_uuid":"data1",
                "rules":[
                    {
                        "rule_id":"rule_id",
                        "grantee_party_ids":[
                            "partyid#1"
                        ],
                        "op_constraints":[
                            {
                                "op_name":"OP_PSI",
                                "constraints": ["r.env.tee.sgx.mr_enclave==\"mr_enclave\" && r.env.tee.platform==\"sgx\""]
                            }
                        ],
                        "columns":[
                            "fields1"
                        ]
                    }
                ]
            }

        "#;
        let policy: Policy = serde_json::from_str(policy_str).unwrap();
        enforcer.enforce(&request, &policy).unwrap();
    }
}
