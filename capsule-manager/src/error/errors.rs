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

use sea_orm::{DbErr, RuntimeErr};
use std::fmt;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
use thiserror;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ErrorCode {
    #[error("Unknown error")]
    Unknown,

    #[error("Unified attestation library error: {:#06x}", errcode)]
    UnifiedAttErr { errcode: i32 },

    #[error("Internal error")]
    InternalErr,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Unsupported error")]
    UnsupportedErr,

    #[error("Crypto error")]
    CryptoErr,

    #[error("Assert err")]
    AssertErr,

    #[error("Invalid Argument")]
    InvalidArgument,

    #[error("Decode error")]
    DecodeError,

    #[error("Not found")]
    NotFound,

    #[error("Already existed")]
    AlreadyExists,

    #[error("Data Integrity Violated")]
    DataIntegrityViolation,
}

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum StatusT {
    // 通用错误码，预留000-099
    // 0 ～ 16 目前对应错误码
    Success = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
    // 从 100 开始为自定义错误码
    // Unified Attestation Error
    UnifiedAttErr = 100,
}

pub fn map_error_to_i32(err: &ErrorCode) -> i32 {
    match err {
        ErrorCode::Unknown => StatusT::Unknown as i32,
        ErrorCode::PermissionDenied => StatusT::PermissionDenied as i32,
        ErrorCode::InvalidArgument => StatusT::InvalidArgument as i32,
        ErrorCode::UnsupportedErr => StatusT::Unimplemented as i32,
        _ => StatusT::Internal as i32,
    }
}

impl From<DbErr> for Error {
    fn from(error: DbErr) -> Self {
        // Convert sea-orm error to our own error type.
        let code = match &error {
            DbErr::Exec(RuntimeErr::SqlxError(sqlx::Error::Database(error))) => {
                match error.code() {
                    Some(code) => {
                        let mut ret_code = ErrorCode::InternalErr;
                        // We check the error code thrown by the database (MySQL in this case),
                        // `23000` means `ER_DUP_KEY`: we have a duplicate key in the table.
                        if code == "23000" {
                            ret_code = ErrorCode::AlreadyExists;
                        }
                        ret_code
                    }
                    None => ErrorCode::InternalErr,
                }
            }
            _ => ErrorCode::InternalErr,
        };

        Error {
            code,
            details: Some(Box::new(error.to_string())),
            location: None,
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error {
            code: ErrorCode::DecodeError,
            details: Some(Box::new(e.to_string())),
            location: None,
        }
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Self {
        Error {
            code: ErrorCode::DecodeError,
            details: Some(Box::new(e.to_string())),
            location: None,
        }
    }
}

impl From<prost::DecodeError> for Error {
    fn from(e: prost::DecodeError) -> Self {
        Error {
            code: ErrorCode::DecodeError,
            details: Some(Box::new(e.to_string())),
            location: None,
        }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error {
            code: ErrorCode::CryptoErr,
            details: Some(Box::new(e.to_string())),
            location: None,
        }
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error {
            code: ErrorCode::DecodeError,
            details: Some(Box::new(e.to_string())),
            location: None,
        }
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Error {
            code: ErrorCode::DecodeError,
            details: Some(Box::new(e.to_string())),
            location: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ErrorLocation {
    line: u32,
    file: &'static str,
}

impl ErrorLocation {
    pub fn new(file: &'static str, line: u32) -> ErrorLocation {
        ErrorLocation { file, line }
    }
}

impl fmt::Display for ErrorLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[line = {}, file = {}]", self.line, self.file)
    }
}

unsafe impl Send for Error {}

#[derive(Debug)]
pub struct Error {
    code: ErrorCode,
    details: Option<Box<String>>,
    location: Option<ErrorLocation>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "err code: {}; ", self.code)?;
        if let Some(ref details) = self.details {
            write!(f, "err detail: {}; ", details)?;
        }
        if let Some(location) = self.location {
            write!(f, "location: {}", location)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl Error {
    pub fn new(code: ErrorCode, details: String, location: Option<ErrorLocation>) -> Error {
        Error {
            code,
            details: Some(Box::new(details)),
            location,
        }
    }

    pub fn errcode(&self) -> i32 {
        map_error_to_i32(&self.code)
    }

    pub fn code(&self) -> &ErrorCode {
        &self.code
    }
}

pub type AuthResult<T> = core::result::Result<T, Error>;
