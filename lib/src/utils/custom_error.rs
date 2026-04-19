use std::collections::BTreeMap;

use async_graphql::{Error, ErrorExtensions, Value};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

// GraphQL Error
// Wrapper type for the original Error
pub struct ExtendedError {
    message: String,
    code: String,
}

impl ExtendedError {
    // Constructor
    pub fn new(message: impl Into<String>, code: &str) -> Self {
        ExtendedError {
            message: message.into(),
            code: code.to_owned(),
        }
    }

    // Setter for status
    pub fn set_status(&mut self, code: &str) {
        self.code = code.to_owned();
    }

    // Build the async_graphql::Error with extensions
    pub fn build(self) -> Error {
        let mut extensions = BTreeMap::new();
        extensions.insert("code".to_string(), Value::from(self.code));

        Error::new(self.message).extend_with(|_err, e| {
            for (key, value) in extensions {
                e.set(key, value);
            }
        })
    }
}

// REST Error
#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    UnprocessableEntity(String),
    Internal(anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody {
    success: bool,
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::UnprocessableEntity(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            ApiError::Internal(err) => {
                tracing::error!("internal error: {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong".to_string(),
                )
            }
        };

        (
            code,
            Json(ErrorBody {
                success: false,
                error: ErrorDetail {
                    code: code.as_str().into(),
                    message,
                },
            }),
        )
            .into_response()
    }
}
