use async_graphql::{Context, Object, Result};
use hyper::StatusCode;
use lib::utils::{custom_error::ExtendedError, models::Email};

use crate::utils;

#[derive(Default)]
pub struct EmailMutation;

#[Object]
impl EmailMutation {
    pub async fn send_email(&self, _ctx: &Context<'_>, email: Email) -> Result<&'static str> {
        let send_email_res = utils::email::send_email(&email).await;

        match send_email_res {
            Ok(send_email_res) => Ok(send_email_res),
            Err(e) => {
                tracing::error!("Error sending email: {}", e);
                Err(ExtendedError::new(
                    "Error sending email",
                    Some(StatusCode::BAD_REQUEST.as_u16()),
                )
                .build())
            }
        }
    }
}
