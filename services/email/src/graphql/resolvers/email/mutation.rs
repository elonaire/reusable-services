use async_graphql::{Context, Object, Result};
use lib::utils::models::Email;

use crate::utils;

#[derive(Default)]
pub struct EmailMutation;

#[Object]
impl EmailMutation {
    pub async fn send_email(&self, _ctx: &Context<'_>, email: Email) -> Result<&'static str> {
        let send_email_res = utils::email::send_email(&email).await;

        match send_email_res {
            Ok(send_email_res) => Ok(send_email_res),
            Err(e) => Err(e.into()),
        }
    }
}
