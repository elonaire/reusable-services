use async_graphql::{Context, Object, Result};
use lib::{
    middleware::auth::false_graphql::confirm_authentication,
    utils::{
        api_responses::synthesize_graphql_response, custom_error::ExtendedError, models::Email,
    },
};

use hyper::{HeaderMap, StatusCode};

use crate::{graphql::schemas::email::GraphQLApiResponse, utils};

#[derive(Default)]
pub struct EmailMutation;

#[Object]
impl EmailMutation {
    pub async fn send_email(
        &self,
        ctx: &Context<'_>,
        email: Email,
    ) -> Result<GraphQLApiResponse<&'static str>> {
        let _authenticated = confirm_authentication(ctx).await?;

        let send_email_res = utils::email::send_email(&email).await;

        match send_email_res {
            Ok(send_email_res) => {
                let api_response =
                    synthesize_graphql_response(ctx, &send_email_res).ok_or_else(|| {
                        tracing::error!("Failed to synthesize response!");
                        ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
                    })?;

                Ok(api_response.into())
            }
            Err(e) => {
                tracing::error!("Error sending email: {}", e);
                Err(
                    ExtendedError::new("Error sending email", StatusCode::BAD_REQUEST.as_str())
                        .build(),
                )
            }
        }
    }
}
