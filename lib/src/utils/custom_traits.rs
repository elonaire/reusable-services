use std::sync::Arc;

use axum::Extension;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

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
