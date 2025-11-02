use async_graphql::{Context, Object, Result};
use lib::{
    middleware::auth::false_graphql::confirm_authentication,
    utils::{custom_error::ExtendedError, models::Email},
};

use hyper::{HeaderMap, StatusCode};

use crate::utils;

#[derive(Default)]
pub struct EmailMutation;

#[Object]
impl EmailMutation {
    pub async fn send_email(&self, ctx: &Context<'_>, email: Email) -> Result<&'static str> {
        let headers = ctx.data::<HeaderMap>().map_err(|e| {
            tracing::error!("Error HeaderMap: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let _authenticated = confirm_authentication(headers).await?;

        let send_email_res = utils::email::send_email(&email).await;

        match send_email_res {
            Ok(send_email_res) => Ok(send_email_res),
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
