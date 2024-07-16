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

use crate::core::model;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::utils::jwt::jwa::{Secret, SignatureAlgorithm};
use crate::utils::serde_custom;
use crate::utils::tool::{
    gen_party_id, get_public_key_from_cert_chain, vec_str_to_vec_u8, verify_cert_chain,
};
use crate::{cm_assert, errno};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::prelude::*;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub enum TeeIdentity {
    #[serde(rename = "sgx")]
    SGX {
        mr_enclave: String,
        mr_signer: String,
    },

    #[serde(rename = "csv")]
    CSV { mr_boot: String },

    #[serde(rename = "tdx")]
    TDX {
        mr_plat: String,
        mr_boot: String,
        mr_ta: String,
    },
}

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub enum TeePlatform {
    #[serde(rename = "sgx")]
    SGX,

    #[serde(rename = "csv")]
    CSV,

    #[serde(rename = "tdx")]
    TDX,
}

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub struct TeeInfo {
    pub platform: TeePlatform,

    #[serde(flatten)]
    pub identity: Option<TeeIdentity>,
}

/// Serialize a jwe header into Base64 URL encoded string
pub fn serialize_datetime<S>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(datetime) = value {
        let value_str = datetime.to_rfc3339_opts(SecondsFormat::Secs, true);
        serializer.serialize_str(&value_str)
    } else {
        serializer.serialize_str("")
    }
}

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub struct Environment {
    // Resource request time
    #[serde(serialize_with = "serialize_datetime")]
    pub request_time: Option<DateTime<Utc>>,

    // The identity of the TEE requesting the resource
    pub tee: Option<TeeInfo>,
}

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
/// Global attributes that describe the common usage behavior of multiple
/// resources
pub struct GlobalAttributes {
    // the identity of data processing user
    pub initiator_party_id: String,

    // data usage scope
    pub scope: String,

    // operators
    // "*": indicate that any operator is allowed
    // "": indicate that no operator is allowed
    pub op_name: String,

    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_custom::format_string::deserialize_from_str"
    )]
    pub env: Option<Environment>,

    #[serde(skip_serializing)]
    #[serde(rename = "global_attrs")]
    pub custom_attrs: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Resource {
    // resource URI
    pub resource_uri: String,

    // used columns of this resource
    pub columns: Vec<String>,

    // custom attributes that apply to this resource
    #[serde(rename = "attrs")]
    pub custom_attrs: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ResourceRequest {
    pub resources: Vec<Resource>,

    #[serde(flatten)]
    pub global_attributes: GlobalAttributes,
}

impl ResourceRequest {
    pub fn iter(&self) -> ResourceRequestIterator {
        ResourceRequestIterator {
            resource_request: self,
            index: 0,
        }
    }
}

pub struct ResourceRequestIterator<'a> {
    resource_request: &'a ResourceRequest,
    index: usize,
}

impl<'a> Iterator for ResourceRequestIterator<'a> {
    type Item = SingleResourceRequest<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.resource_request.resources.len() {
            self.index += 1;
            Some(SingleResourceRequest {
                resource_uri: &self.resource_request.resources[self.index - 1].resource_uri,
                columns: &self.resource_request.resources[self.index - 1].columns,
                custom_attrs: self.resource_request.resources[self.index - 1]
                    .custom_attrs
                    .as_ref(),
                global_attributes: &self.resource_request.global_attributes,
            })
        } else {
            None
        }
    }
}

#[derive(Serialize, PartialEq, Debug)]
/// Single resource request with related usage behavior
pub struct SingleResourceRequest<'a> {
    // resource URI
    pub resource_uri: &'a String,

    // used columns of this resource
    pub columns: &'a Vec<String>,

    // custom attributes that apply to this resource
    #[serde(skip_serializing)]
    pub custom_attrs: Option<&'a serde_json::Value>,

    #[serde(flatten)]
    // common attributes reference shared with other resources
    pub global_attributes: &'a GlobalAttributes,
}

impl<'a> SingleResourceRequest<'a> {
    pub fn to_json_string(&self) -> Result<String, Error> {
        // convert pre-defined attributes to json object
        let mut reorganized_request: serde_json::Value =
            serde_json::from_str(serde_json::to_string(self)?.as_str())?;

        // merge the custom attributes, one from operator-specific attributes and one
        // from global attributes.
        let mut custom_attrs = serde_json::Value::Null;
        if let Some(ref global_custom_attrs) = self.global_attributes.custom_attrs {
            crate::utils::json_merger::merge(&mut custom_attrs, global_custom_attrs)
        }
        // operator-specific attributes will override the attributes has already
        // occurred in global attributes
        if let Some(ref global_custom_attrs) = self.custom_attrs {
            crate::utils::json_merger::merge(&mut custom_attrs, global_custom_attrs)
        }

        if let Some(object) = reorganized_request.as_object_mut() {
            if !custom_attrs.is_null() {
                object.insert("attrs".to_owned(), custom_attrs);
            }
        }

        Ok(serde_json::to_string(&reorganized_request)?)
    }
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub enum VoteType {
    #[serde(rename = "TEE_DOWNLOAD")]
    TeeDownload,

    #[serde(rename = "NODE_ROUTE")]
    NodeRoute,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RequestBody {
    //unique vote id
    pub vote_request_id: Option<String>,

    //vote type
    #[serde(rename = "type")]
    pub vote_type: VoteType,

    //vote initiator
    pub initiator: Option<String>,

    //vote_counter
    pub vote_counter: Option<String>,

    //vote participants
    pub voters: Option<Vec<String>>,

    //executors
    pub executors: Option<Vec<String>>,

    //approved_threshold
    pub approved_threshold: u32,

    //approved_action
    pub approved_action: Option<String>,

    //rejected_action
    pub rejected_action: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VoteRequest {
    pub cert_chain: Vec<String>,

    #[serde(deserialize_with = "serde_custom::format_string::deserialize_from_base64_str")]
    pub body: Vec<u8>,

    #[serde(deserialize_with = "serde_custom::format_string::deserialize_from_base64_str")]
    #[serde(rename = "vote_request_signature")]
    pub signature: Vec<u8>,
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub enum Action {
    #[serde(rename = "APPROVE")]
    Approve,

    #[serde(rename = "REJECT")]
    Reject,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct InviteBody {
    //unique vote id
    pub vote_request_id: Option<String>,

    //participant
    pub voter: Option<String>,

    pub action: Action,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VoteInvite {
    pub cert_chain: Vec<String>,

    #[serde(deserialize_with = "serde_custom::format_string::deserialize_from_base64_str")]
    pub body: Vec<u8>,

    #[serde(deserialize_with = "serde_custom::format_string::deserialize_from_base64_str")]
    #[serde(rename = "voter_signature")]
    pub signature: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VoteResult {
    pub vote_request: VoteRequest,

    pub vote_invite: Vec<VoteInvite>,
}

impl VoteResult {
    // verify vote_request sign
    pub fn verify_sign(&self) -> AuthResult<()> {
        let pk = get_public_key_from_cert_chain(
            &vec_str_to_vec_u8(&self.vote_request.cert_chain),
            0,
            "PEM",
        )?;
        // signature
        SignatureAlgorithm::RS256.verify(
            &self.vote_request.signature,
            STANDARD.encode(&self.vote_request.body).as_bytes(),
            &Secret::PublicKey(pk),
        )?;

        Ok(())
    }

    // verify vote_request
    pub fn verify_request(&self, resource_uri: &str) -> AuthResult<()> {
        // verify signature
        self.verify_sign()?;

        // verify resource uri
        let body: RequestBody =
            serde_json::from_str(std::str::from_utf8(&self.vote_request.body)?)?;
        let action: model::ApproveAction = body
            .approved_action
            .ok_or(errno!(
                ErrorCode::InvalidArgument,
                "approve action is empty"
            ))?
            .parse()?;
        cm_assert!(
            action.resource_uri == resource_uri,
            "{} {} is not the same as expected",
            action.resource_uri,
            resource_uri
        );
        cm_assert!(
            body.vote_type == VoteType::TeeDownload,
            "type is not tee download"
        );
        Ok(())
    }

    // verify each vote_invite
    pub fn verify_each_vote(&self, invite: &VoteInvite) -> AuthResult<()> {
        let pk = get_public_key_from_cert_chain(&vec_str_to_vec_u8(&invite.cert_chain), 0, "PEM")?;
        let data = [
            STANDARD.encode(&invite.body).as_bytes(),
            STANDARD.encode(&self.vote_request.signature).as_bytes(),
        ]
        .concat();
        SignatureAlgorithm::RS256.verify(&invite.signature, &data, &Secret::PublicKey(pk))?;
        // vote action
        let invite_body: InviteBody = serde_json::from_str(std::str::from_utf8(&invite.body)?)?;
        cm_assert!(
            invite_body.action == Action::Approve,
            "vote request_id {:?} action is not approve",
            invite_body.vote_request_id
        );
        Ok(())
    }

    // verify vote_invite sign and all voters is APPROVE
    pub fn verify_vote(&self, ancestors: &Vec<String>) -> AuthResult<()> {
        let mut count = 0;
        for invite in self.vote_invite.iter() {
            let pk = get_public_key_from_cert_chain(
                &vec_str_to_vec_u8(&invite.cert_chain),
                invite.cert_chain.len() - 1,
                "PEM",
            )?;
            let party_id = gen_party_id(&pk)?;
            if ancestors.contains(&party_id) {
                self.verify_each_vote(invite)?;
                count += 1;
            }
        }
        cm_assert!(count >= ancestors.len(), "not all ancestors are voting");
        Ok(())
    }

    // verify the request's identifier is party
    pub fn verify_identifier(&self, party_id: &str) -> AuthResult<()> {
        verify_cert_chain(&vec_str_to_vec_u8(&self.vote_request.cert_chain), "PEM")?;
        let pk = get_public_key_from_cert_chain(
            &vec_str_to_vec_u8(&self.vote_request.cert_chain),
            self.vote_request.cert_chain.len() - 1,
            "PEM",
        )?;
        cm_assert!(
            party_id == gen_party_id(&pk)?,
            "party_id {} is wrong derived from public key",
            party_id
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use chrono::{DateTime, Utc};

    use super::{
        Environment, GlobalAttributes, InviteBody, RequestBody, ResourceRequest,
        SingleResourceRequest, TeeIdentity,
    };

    #[test]
    fn test_vote_result_serde() {
        let vote_request_json = r#"
        {
            "type": "TEE_DOWNLOAD",
            "approved_threshold": 1,
            "approved_action": "tee/download,join_uuid"
        }
        "#;

        let vote_request: RequestBody = serde_json::from_str(vote_request_json).unwrap();

        let vote_invite_json = "{\"action\": \"APPROVE\"}";

        let vote_invite: InviteBody = serde_json::from_str(vote_invite_json).unwrap();
    }

    #[test]
    fn test_global_attributes_serde() {
        let expect = r#"
        {
            "initiator_party_id":"GCBACCQCQIAQCAHROV4EGQ33N72D6A6N3SYEIEFKU6RKFBJDQMZQ",
            "op_name":"OP_PSI",
            "scope": "",
            "env": "",
            "resources":[
                {
                    "resource_uri":"data_uuid",
                    "columns":[
                        "col"
                    ]
                }
            ]
        }
        "#;
        let global: ResourceRequest = serde_json::from_str(expect).unwrap();
        for r in global.iter() {
            println!("{}", r.to_json_string().unwrap());
        }
    }

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
            op_name: "*".to_owned(),
            env: Some(Environment {
                request_time: Some("2023-08-24T12:55:52Z".parse::<DateTime<Utc>>().unwrap()),
                tee: Some(crate::core::model::request::TeeInfo {
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

        let expect = r#"
            {
                "attrs":{
                    "xgb":{
                        "tree_num":1
                    }
                },
                "columns":[
                    "fields1"
                ],
                "env":{
                    "request_time":"2023-08-24T12:55:52Z",
                    "tee":{
                        "sgx":{
                            "mr_enclave":"mr_enclave",
                            "mr_signer":"mr_signer"
                        },
                        "platform": "sgx"
                    }
                },
                "initiator_party_id":"partyid#1",
                "op_name":"*",
                "resource_uri":"data1",
                "scope":"workspace#1"
            }
        "#;

        assert_json_eq!(
            serde_json::from_str::<serde_json::Value>(expect).unwrap(),
            serde_json::from_str::<serde_json::Value>(request.to_json_string().unwrap().as_str())
                .unwrap()
        );

        // assert_json_eq!(serde_json::json!(expect),
        // serde_json::json!(request.to_json_string().unwrap()));
    }
}
