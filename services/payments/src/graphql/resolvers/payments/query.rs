use std::{env, sync::Arc};

use async_graphql::{Context, Object, Result};
use axum::Extension;
use hyper::{HeaderMap, StatusCode};
use lib::{
    middleware::auth::false_graphql::confirm_authentication, utils::custom_error::ExtendedError,
};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::graphql::schemas::general::{Currency, FetchCurrenciesQueryFilters};

#[derive(Default)]
pub struct PaymentQuery;

#[Object]
impl PaymentQuery {
    pub async fn fetch_currencies(
        &self,
        ctx: &Context<'_>,
        filters: Option<FetchCurrenciesQueryFilters>,
    ) -> Result<Vec<Currency>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let filter_query = match &filters {
            Some(_existing_filters) => {
                r#"
                BEGIN TRANSACTION;
                RETURN IF $filters != NONE {
              		RETURN IF $filters.currency_id != NONE AND string::len($filters.currency_id) > 0 {
                        LET $currency_record = type::thing('currency', $filters.currency_id);
                        IF !$currency_record.exists() {
                            []
                   	    };
                        (SELECT * FROM currency WHERE id = $currency_record)
                    }
                    ELSE IF $filters.code != NONE AND string::len($filters.code) > 0 {
                        (SELECT * FROM currency WHERE code = $filters.code)
                    }
                    ELSE IF $filters.numeric != NONE AND string::len($filters.numeric) > 0 {
                        (SELECT * FROM currency WHERE numeric = $filters.numeric)
                    }
                    ELSE IF $filters.search_term != NONE AND string::len($filters.search_term) > 0 {
                        (SELECT * FROM currency WHERE name @@ $filters.search_term)
                    }
                    ELSE {
                        []
                    };
                };
                COMMIT TRANSACTION;
                "#
            }
            None => "(SELECT * FROM currency)",
        };

        let mut fetch_currencies_query = db
            .query(filter_query)
            .bind(("filters", filters))
            .await
            .map_err(|e| {
                tracing::error!("Error fetching currencies: {}", e);
                ExtendedError::new(
                    "Error fetching currencies",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        let response: Vec<Currency> = fetch_currencies_query.take(0).map_err(|e| {
            tracing::error!("currencies deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        Ok(response)
    }
}
