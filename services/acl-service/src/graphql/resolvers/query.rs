use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use dotenvy::dotenv;
use hyper::{HeaderMap, StatusCode};
use lib::utils::{custom_error::ExtendedError, models::AuthStatus};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{graphql::schemas::user::UserOutput, utils::auth::confirm_auth};

pub struct Query;

#[Object]
impl Query {
    async fn get_users(&self, ctx: &Context<'_>) -> Result<Vec<UserOutput>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let response: Vec<UserOutput> = db.select("user").await.map_err(|e| {
            tracing::error!("Error fetching users: {}", e);
            ExtendedError::new(
                "Error fetching users",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build()
        })?;

        Ok(response)
    }

    async fn get_user(&self, ctx: &Context<'_>, id: String) -> Result<UserOutput> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let user: Option<UserOutput> = db.select(("user", id.as_str())).await.map_err(|e| {
            tracing::error!("Error fetching user: {}", e);
            ExtendedError::new(
                "Error fetching user",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build()
        })?;

        match user {
            Some(user) => Ok(user),
            None => Err(
                ExtendedError::new("User not found", Some(StatusCode::NOT_FOUND.as_u16())).build(),
            ),
        }
    }

    async fn check_auth(&self, ctx: &Context<'_>) -> Result<AuthStatus> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
        let header_map = ctx.data_opt::<HeaderMap>();

        confirm_auth(header_map, db).await.map_err(Error::from)
    }
}
