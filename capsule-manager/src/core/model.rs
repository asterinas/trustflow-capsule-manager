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

pub mod policy;
pub mod request;

use crate::errno;
use crate::error::errors::{Error, ErrorCode, ErrorLocation};
use serde::Serialize;
use std::fmt;

#[derive(Default)]
pub struct ResourceUri {
    pub data_uuid: String,

    pub partition_id: Option<String>,

    pub segment_id: Option<u32>,

    pub shard_id: Option<u32>,
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

use std::str;

impl str::FromStr for ResourceUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split_strs = s.split('/').collect::<Vec<&str>>();
        let mut uri = ResourceUri::default();
        for (i, &part) in split_strs.iter().enumerate() {
            if i == 0 {
                if part.is_empty() {
                    return Err(errno!(ErrorCode::InvalidArgument, "data uuid is empty"));
                }
                uri.data_uuid = part.to_owned();
            } else if i == 1 {
                match part.is_empty() {
                    true => break,
                    false => uri.partition_id = Some(part.to_owned()),
                }
            } else if i == 2 {
                match part.is_empty() {
                    true => break,
                    false => {
                        uri.segment_id = Some(part.parse().map_err(|e| {
                            errno!(ErrorCode::InvalidArgument, "parse int failed, {:?}", e)
                        })?)
                    }
                }
            } else if i == 3 {
                match part.is_empty() {
                    true => break,
                    false => {
                        uri.shard_id = Some(part.parse().map_err(|e| {
                            errno!(ErrorCode::InvalidArgument, "parse int failed, {:?}", e)
                        })?)
                    }
                }
            }
        }
        Ok(uri)
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut uri = self.data_uuid.clone();
        if let Some(ref partition_id) = self.partition_id {
            uri.push_str(partition_id.as_str());
            if let Some(ref segment_id) = self.segment_id {
                uri.push_str(segment_id.to_string().as_str());
                if let Some(ref shard_id) = self.shard_id {
                    uri.push_str(shard_id.to_string().as_str());
                }
            }
        }
        write!(f, "{uri}")
    }
}

// for example, "tee/download, data_uuid"
#[derive(Default, Debug)]
pub struct ApproveAction {
    pub action_name: String,

    pub resource_uri: String,
}

impl str::FromStr for ApproveAction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split_strs = s.split(',').collect::<Vec<&str>>();
        let mut action = ApproveAction::default();
        for (i, &part) in split_strs.iter().enumerate() {
            if i == 0 {
                if part.is_empty() {
                    return Err(errno!(ErrorCode::InvalidArgument, "action_name is empty"));
                }
                action.action_name = part.to_owned();
            } else if i == 1 {
                if part.is_empty() {
                    return Err(errno!(ErrorCode::InvalidArgument, "resource_uri is empty"));
                }
                action.resource_uri = part.to_owned();
            } else {
                break;
            }
        }
        Ok(action)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_uri_serialization() {
        use super::ResourceUri;
        let resource_uri = ResourceUri {
            data_uuid: String::from("data_uuid"),
            partition_id: None,
            segment_id: None,
            shard_id: None,
        };
        assert_eq!(resource_uri.to_string().as_str(), "data_uuid");
    }
}
