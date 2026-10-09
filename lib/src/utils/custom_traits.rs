use std::sync::Arc;

use async_graphql::Context;
use axum::{
    http::{HeaderName, HeaderValue},
    Extension,
};
use hyper::HeaderMap;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use crate::utils::models::{AxumAuthContext, GrpcAuthContext, MetadataView};

/// A trait to get the Surreal<Client> for generic functions that use the Surreal Client
pub trait AsSurrealClient {
    fn as_client(&self) -> &Surreal<SurrealClient>;
}

// Implement for Arc<Surreal<Client>>
impl AsSurrealClient for Arc<Surreal<SurrealClient>> {
    fn as_client(&self) -> &Surreal<SurrealClient> {
        self.as_ref()
    }
}

// Implement for Extension<Arc<Surreal<Client>>>
impl AsSurrealClient for Extension<Arc<Surreal<SurrealClient>>> {
    fn as_client(&self) -> &Surreal<SurrealClient> {
        self.0.as_ref()
    }
}

#[derive(Debug)]
pub enum MetadataError {
    InvalidKey { key: String, source: String },
    InvalidValue { key: String, source: String },
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey { key, source } => write!(f, "invalid metadata key `{key}`: {source}"),
            Self::InvalidValue { key, source } => {
                write!(f, "invalid metadata value for `{key}`: {source}")
            }
        }
    }
}

impl std::error::Error for MetadataError {}

#[async_trait::async_trait]
pub trait AuthMetadataContext: Send + Sync {
    fn request_metadata(&self) -> MetadataView<'_>;
    async fn set_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError>;
    async fn append_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError>;
}

#[async_trait::async_trait]
impl AuthMetadataContext for Context<'_> {
    fn request_metadata(&self) -> MetadataView<'_> {
        MetadataView::Http(self.data_opt::<HeaderMap>())
    }

    async fn set_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError> {
        let name =
            HeaderName::from_bytes(key.as_bytes()).map_err(|e| MetadataError::InvalidKey {
                key: key.into(),
                source: e.to_string(),
            })?;
        let val = HeaderValue::from_str(value).map_err(|e| MetadataError::InvalidValue {
            key: key.into(),
            source: e.to_string(),
        })?;
        self.insert_http_header(name, val);
        Ok(())
    }

    async fn append_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError> {
        let name =
            HeaderName::from_bytes(key.as_bytes()).map_err(|e| MetadataError::InvalidKey {
                key: key.into(),
                source: e.to_string(),
            })?;
        let val = HeaderValue::from_str(value).map_err(|e| MetadataError::InvalidValue {
            key: key.into(),
            source: e.to_string(),
        })?;
        self.append_http_header(name, val);
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuthMetadataContext for AxumAuthContext {
    fn request_metadata(&self) -> MetadataView<'_> {
        MetadataView::Http(Some(&self.request_headers))
    }

    async fn set_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError> {
        let name =
            HeaderName::from_bytes(key.as_bytes()).map_err(|e| MetadataError::InvalidKey {
                key: key.into(),
                source: e.to_string(),
            })?;
        let val = HeaderValue::from_str(value).map_err(|e| MetadataError::InvalidValue {
            key: key.into(),
            source: e.to_string(),
        })?;
        let mut headers = self.response_headers.lock().await;
        headers.insert(name, val);
        Ok(())
    }

    async fn append_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError> {
        let name =
            HeaderName::from_bytes(key.as_bytes()).map_err(|e| MetadataError::InvalidKey {
                key: key.into(),
                source: e.to_string(),
            })?;
        let val = HeaderValue::from_str(value).map_err(|e| MetadataError::InvalidValue {
            key: key.into(),
            source: e.to_string(),
        })?;
        let mut headers = self.response_headers.lock().await;
        headers.append(name, val);
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuthMetadataContext for GrpcAuthContext {
    fn request_metadata(&self) -> MetadataView<'_> {
        MetadataView::Grpc(Some(&self.request_metadata))
    }

    async fn set_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError> {
        use tonic::metadata::MetadataKey;

        let key_parsed =
            MetadataKey::from_bytes(key.as_bytes()).map_err(|e| MetadataError::InvalidKey {
                key: key.into(),
                source: e.to_string(),
            })?;
        let val = value
            .parse()
            .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                MetadataError::InvalidValue {
                    key: key.into(),
                    source: e.to_string(),
                }
            })?;
        let mut md = self.response_metadata.lock().await;
        md.insert(key_parsed, val);
        Ok(())
    }

    async fn append_response_metadata(&self, key: &str, value: &str) -> Result<(), MetadataError> {
        use tonic::metadata::MetadataKey;

        let key_parsed =
            MetadataKey::from_bytes(key.as_bytes()).map_err(|e| MetadataError::InvalidKey {
                key: key.into(),
                source: e.to_string(),
            })?;
        let val = value
            .parse()
            .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                MetadataError::InvalidValue {
                    key: key.into(),
                    source: e.to_string(),
                }
            })?;
        let mut md = self.response_metadata.lock().await;
        md.append(key_parsed, val);
        Ok(())
    }
}
