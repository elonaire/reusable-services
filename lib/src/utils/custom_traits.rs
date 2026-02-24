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

#[async_trait::async_trait]
pub trait AuthMetadataContext: Send + Sync {
    /// Read request metadata (HTTP headers / gRPC metadata)
    fn request_metadata(&self) -> MetadataView<'_>;
    /// Mutate outgoing metadata
    async fn set_response_metadata(&self, key: &str, value: &str);
    async fn append_response_metadata(&self, key: &str, value: &str);
}

#[async_trait::async_trait]
impl AuthMetadataContext for Context<'_> {
    fn request_metadata(&self) -> MetadataView<'_> {
        MetadataView::Http(self.data_opt::<HeaderMap>())
    }

    async fn set_response_metadata(&self, key: &str, value: &str) {
        let name = HeaderName::from_bytes(key.as_bytes()).unwrap();
        let val = HeaderValue::from_str(value).unwrap();
        self.insert_http_header(name, val);
    }

    async fn append_response_metadata(&self, key: &str, value: &str) {
        let name = HeaderName::from_bytes(key.as_bytes()).unwrap();
        let val = HeaderValue::from_str(value).unwrap();
        self.append_http_header(name, val);
    }
}

#[async_trait::async_trait]
impl AuthMetadataContext for AxumAuthContext {
    fn request_metadata(&self) -> MetadataView<'_> {
        MetadataView::Http(Some(&self.request_headers))
    }

    async fn set_response_metadata(&self, key: &str, value: &str) {
        let name = HeaderName::from_bytes(key.as_bytes()).unwrap();
        let val = HeaderValue::from_str(value).unwrap();
        let mut headers = self.response_headers.lock().await;
        headers.insert(name, val);
    }

    async fn append_response_metadata(&self, key: &str, value: &str) {
        let name = HeaderName::from_bytes(key.as_bytes()).unwrap();
        let val = HeaderValue::from_str(value).unwrap();
        let mut headers = self.response_headers.lock().await;
        headers.append(name, val);
    }
}

#[async_trait::async_trait]
impl AuthMetadataContext for GrpcAuthContext {
    fn request_metadata(&self) -> MetadataView<'_> {
        MetadataView::Grpc(Some(&self.request_metadata))
    }

    async fn set_response_metadata(&self, key: &str, value: &str) {
        use tonic::metadata::MetadataKey;
        let key = MetadataKey::from_bytes(key.as_bytes()).unwrap();
        let mut md = self.response_metadata.lock().await;
        md.insert(key, value.parse().unwrap());
    }

    async fn append_response_metadata(&self, key: &str, value: &str) {
        use tonic::metadata::MetadataKey;
        let key = MetadataKey::from_bytes(key.as_bytes()).unwrap();
        let mut md = self.response_metadata.lock().await;
        md.append(key, value.parse().unwrap());
    }
}
