use std::sync::Arc;

use async_graphql::Context;
use axum::Extension;
// use lib::utils::custom_error::ExtendedError;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use crate::utils::models::ForeignKey;
use serde::{Deserialize, Serialize};

/// Integration method to set foreign keys in the target service database(GraphQL)
pub async fn add_foreign_key_if_not_exists<F: for<'de> Deserialize<'de> + Serialize>(
    ctx: &Context<'_>,
    foreign_key: ForeignKey,
) -> Option<F> {
    let db = ctx
        .data::<Extension<Arc<Surreal<SurrealClient>>>>()
        .unwrap();

    let search_query = format!(
        "SELECT * FROM type::table($table) WHERE {} = $value LIMIT 1",
        foreign_key.column
    );

    let result = db
        .query(&search_query)
        .bind(("table", foreign_key.table.clone()))
        .bind(("value", foreign_key.foreign_key.clone()))
        .await;

    match result {
        Ok(mut result) => {
            let response: Option<F> = result.take(0).unwrap();
            if response.is_none() {
                let insert_query = format!(
                    "INSERT INTO {} ({}) VALUES ($value)",
                    &foreign_key.table, &foreign_key.column
                );
                let record_add_res = db
                    .query(insert_query)
                    .bind(("value", foreign_key.foreign_key.clone()))
                    .await;

                match record_add_res {
                    Ok(mut res) => {
                        let res: Option<F> = res.take(0).unwrap();
                        res
                    }
                    Err(_) => None,
                }
            } else {
                // return true;
                response
            }
        }
        Err(_) => None,
    }
}

/// Integration method to set foreign keys in the target service database(REST)
pub async fn add_foreign_key_if_not_exists_rest<F: for<'de> Deserialize<'de> + Serialize>(
    db: &Arc<Surreal<SurrealClient>>,
    foreign_key: ForeignKey,
) -> Option<F> {
    let search_query = format!(
        "SELECT * FROM type::table($table) WHERE {} = $value LIMIT 1",
        &foreign_key.column
    );

    let result = db
        .query(&search_query)
        .bind(("table", foreign_key.table.clone()))
        .bind(("value", foreign_key.foreign_key.clone()))
        .await;

    match result {
        Ok(mut result) => {
            let response: Option<F> = result.take(0).unwrap();
            if response.is_none() {
                let insert_query = format!(
                    "INSERT INTO {} ({}) VALUES ($value)",
                    &foreign_key.table, &foreign_key.column
                );
                let record_add_res = db
                    .query(insert_query)
                    .bind(("value", foreign_key.foreign_key.clone()))
                    .await;

                match record_add_res {
                    Ok(mut res) => {
                        let res: Option<F> = res.take(0).unwrap();
                        res
                    }
                    Err(_) => None,
                }
            } else {
                // return true;
                response
            }
        }
        Err(_) => None,
    }
}
