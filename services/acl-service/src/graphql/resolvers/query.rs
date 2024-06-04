use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use dotenvy::dotenv;
use lib::utils::auth::AuthStatus;
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::user::User,
    middleware::oauth::confirm_auth,
};

// use super::mutation::AuthClaim;

pub struct Query;

#[Object]
impl Query {
    async fn get_users(&self, ctx: &Context<'_>) -> Result<Vec<User>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let response = db
            .select("user")
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(response)
    }

    async fn get_user(&self, ctx: &Context<'_>, id: String) -> Result<User> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let user: Option<User> = db
            .select(("user", id.as_str()))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        // let user: Option<User> = response.take(0)?;

        match user {
            Some(user) => Ok(user),
            None => Err(Error::new("User not found")),
        }
    }

    async fn check_auth(&self, ctx: &Context<'_>) -> Result<AuthStatus> {
        dotenv().ok();
        // let jwt_secret =
        //     env::var("JWT_SECRET").expect("Missing the JWT_SECRET environment variable.");
        // let jwt_refresh_secret = env::var("JWT_REFRESH_SECRET")
        //     .expect("Missing the JWT_REFRESH_SECRET environment variable.");
        confirm_auth(ctx).await
    }
}
