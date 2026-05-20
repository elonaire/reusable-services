use std::sync::Arc;

use async_graphql::{Context, Object, Result};
use axum::Extension;
use hyper::StatusCode;
use lib::utils::{api_responses::synthesize_graphql_response, custom_error::ExtendedError};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::graphql::schemas::{
    general::{Currency, FetchCurrenciesQueryFilters},
    shared::GraphQLApiResponse,
};

#[derive(Default)]
pub struct PaymentQuery;

#[Object]
impl PaymentQuery {
    pub async fn fetch_currencies(
        &self,
        ctx: &Context<'_>,
        filters: Option<FetchCurrenciesQueryFilters>,
    ) -> Result<GraphQLApiResponse<Vec<Currency>>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let mut fetch_currencies_query = db
            .query(
                r#"
                IF $filters != NONE {
                    LET $currency_id = $filters.currency_id;
                    LET $currency_code = $filters.code;
                    LET $currency_numeric = $filters.numeric;
                    LET $search_term = $filters.search_term;
                    IF $currency_id != NONE AND string::len($currency_id) > 0 {
                        LET $currency_record = type::record('currency', $currency_id);

                        (SELECT * FROM currency WHERE id = $currency_record)
                    }
                    ELSE IF $currency_code != NONE AND string::len($currency_code) > 0 {
                        (SELECT * FROM currency WHERE code = $currency_code)
                    }
                    ELSE IF $currency_numeric != NONE AND string::len($currency_numeric) > 0 {
                        (SELECT * FROM currency WHERE numeric = $currency_numeric)
                    }
                    ELSE IF $search_term != NONE AND string::len($search_term) > 0 {
                        (SELECT * FROM currency WHERE name @@ $search_term)
                    }
                    ELSE {
                        []
                    };
                } ELSE {
                    (SELECT * FROM currency)
                };
                "#,
            )
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

        let api_response = synthesize_graphql_response(ctx, &response, None).ok_or_else(|| {
            tracing::error!("Failed to synthesize response!");
            ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        Ok(api_response.into())
    }
}
