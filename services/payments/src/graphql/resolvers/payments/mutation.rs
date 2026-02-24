// use crate::graphql::schemas::general::ExchangeRatesResponse;
use async_graphql::{Context, Object, Result};
use axum::http::HeaderMap;
use hyper::StatusCode;
use lib::{
    middleware::auth::false_graphql::confirm_authentication,
    utils::{
        api_responses::synthesize_graphql_response,
        custom_error::ExtendedError,
        models::{InitializePaymentResponse, UserPaymentDetails},
    },
};

use crate::{
    graphql::schemas::shared::GraphQLApiResponse, utils::payments::initiate_payment_integration,
};

#[derive(Default)]
pub struct PaymentMutation;

#[Object]
impl PaymentMutation {
    pub async fn initiate_payment(
        &self,
        ctx: &Context<'_>,
        mut user_payment_details: UserPaymentDetails,
    ) -> Result<GraphQLApiResponse<InitializePaymentResponse>> {
        let auth_status = confirm_authentication(ctx).await?;
        let auth_status_ref = &auth_status;

        let payment_req = initiate_payment_integration(&mut user_payment_details).await?;

        let api_response = synthesize_graphql_response(ctx, &payment_req, Some(auth_status_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }
}
