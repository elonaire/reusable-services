use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use dotenvy::dotenv;
use lib::utils::auth::AuthStatus;
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::user::UserOutput,
    middleware::oauth::confirm_auth,
};

// use super::mutation::AuthClaim;

pub struct Query;

#[Object]
impl Query {
    async fn get_users(&self, ctx: &Context<'_>) -> Result<Vec<UserOutput>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let response = db
            .select("user")
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(response)
    }

    async fn get_user(&self, ctx: &Context<'_>, id: String) -> Result<UserOutput> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let user: Option<UserOutput> = db
            .select(("user", id.as_str()))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        match user {
            Some(user) => Ok(user),
            None => Err(Error::new("User not found")),
        }
    }

    async fn check_auth(&self, ctx: &Context<'_>) -> Result<AuthStatus> {
        dotenv().ok();
        
        confirm_auth(ctx).await
    }
}
