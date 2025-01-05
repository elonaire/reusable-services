use std::sync::Arc;

use crate::graphql::schemas::general::UploadedFile;
use async_graphql::{Context, Error, Object, Result};
use axum::{http::HeaderMap, Extension};
use lib::utils::custom_error::ExtendedError;
use surrealdb::{engine::remote::ws::Client, Surreal};

#[derive(Default)]
pub struct FileMutation;

#[Object]
impl FileMutation {
    pub async fn health(&self, your_name: String) -> String {
        format!("Hi {}, Files Service is Online!", your_name)
    }
}
