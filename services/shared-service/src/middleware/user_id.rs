use std::sync::Arc;

use async_graphql::Context;
use axum::Extension;
// use lib::utils::custom_error::ExtendedError;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use crate::graphql::schemas::user::User;

pub async fn add_user_id_if_not_exists(ctx: &Context<'_>, user_id: String) -> bool {
    let db = ctx
    .data::<Extension<Arc<Surreal<SurrealClient>>>>()
    .unwrap();

    let result = db
                .query("SELECT * FROM type::table($table) WHERE user_id = $user_id LIMIT 1")
                .bind(("table", "user_id"))
                .bind(("user_id", user_id.clone()))
                .await;

    match result {
        Ok(mut result) => {
            let response: Option<User> = result.take(0).unwrap();
            if response.is_none() {
                let user_id_add_res = db
                    .query("INSERT INTO user_id (user_id) VALUES ($user_id)")
                    .bind(("user_id", user_id))
                    .await;

                match user_id_add_res {
                    Ok(_) => true,
                    Err(_) => false
                }
            } else {
                return true;
            }
        }
        Err(_) => {
            // return Err(ExtendedError::new("Failed to add user_id"));
            return false;
        }
    }
}