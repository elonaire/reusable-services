use std::sync::Arc;

use async_graphql::{Context, Result, SimpleObject};
use axum::{http::HeaderValue, Extension};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use surrealdb::{engine::remote::ws::Client, Surreal};

use super::custom_error::ExtendedError;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct AuthStatus {
    pub is_auth: bool,
    pub sub: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymKey {
    pub name: String,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct AuthClaim {
    // pub sub: String,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct DecodeTokenResponse {
    #[serde(rename = "decodeToken")]
    pub decode_token: String,
}

pub async fn decode_token(ctx: &Context<'_>, token_header: &HeaderValue) -> Result<AuthStatus> {
    let token = token_header.to_str().unwrap().strip_prefix("Bearer ");

    match token {
        Some(token) => {
            println!("token: {:?}", token);
            let key: Vec<u8>;

            let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
            let mut result = db
                .query("SELECT * FROM type::table($table) WHERE name = 'jwt_key' LIMIT 1")
                .bind(("table", "crypto_key"))
                .await?;
            let response: Option<SymKey> = result.take(0)?;

            match &response {
                Some(key_container) => {
                    println!("key_container: {:?}", key_container.key.clone());
                    key = key_container.key.clone();
                }
                None => {
                    // key = HS256Key::generate().to_bytes();
                    return Err(
                        ExtendedError::new("Not Authorized!", Some(403.to_string())).build()
                    );
                }
            }

            let converted_key = HS256Key::from_bytes(&key);

            let _claims = converted_key.verify_token::<AuthClaim>(&token, None);

            println!("claims: {:?}", _claims);

            match &_claims {
                Ok(_) => {
                    let sub = _claims
                        .as_ref()
                        .unwrap()
                        .subject
                        .as_ref()
                        .map(|t| t.to_string())
                        .unwrap_or("".to_string());
                    let is_auth = true;
                    Ok(AuthStatus {
                        is_auth,
                        sub: sub.to_string(),
                    })
                }
                Err(e) => Err(ExtendedError::new(e.to_string(), Some(403.to_string())).build()),
            }
        }
        None => Err(
            ExtendedError::new("Invalid token format".to_string(), Some(403.to_string())).build(),
        ),
    }
}
