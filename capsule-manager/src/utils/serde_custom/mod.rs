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

//! Custom serialization and deserialization modules
//!
//! In general, users should not need to invoke these manually. These are
//! exposed for potential use in your applications, should you wish to make
//! extensions to the implementations provided.
pub(crate) mod byte_sequence;
pub(crate) mod format_string;
pub(crate) mod jwe_header;
pub(crate) mod jws_header;
