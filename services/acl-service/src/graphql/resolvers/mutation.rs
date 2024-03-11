use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use hyper::header::SET_COOKIE;
use jwt_simple::prelude::*;
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    auth::oauth::{initiate_auth_code_grant_flow, navigate_to_redirect_url},
    graphql::schemas::{
        role::SystemRole,
        user::{AuthDetails, User, UserLogins, SymKey},
    },
};

pub struct Mutation;
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthClaim {
    // pub sub: String,
    pub roles: Vec<String>,
}

#[Object]
impl Mutation {
    async fn sign_up(&self, ctx: &Context<'_>, mut user: User) -> Result<Vec<User>> {
        user.password = bcrypt::hash(user.password, bcrypt::DEFAULT_COST).unwrap();
        user.dob = chrono::DateTime::parse_from_rfc3339(&user.dob)
            .unwrap()
            .to_rfc3339();

        // User signup
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
        let response: Vec<User> = db
            .create("user")
            .content(User {
                created_at: Some(chrono::Utc::now().to_rfc3339()),
                updated_at: Some(chrono::Utc::now().to_rfc3339()),
                oauth_client: None,
                ..user
            })
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(response)
    }

    async fn create_user_role(
        &self,
        ctx: &Context<'_>,
        role: SystemRole,
    ) -> Result<Vec<SystemRole>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
        let response = db
            .create("role")
            .content(SystemRole { ..role })
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(response)
    }

    async fn sign_in(
        &self,
        ctx: &Context<'_>,
        raw_user_details: UserLogins,
    ) -> Result<AuthDetails> {
        let user_details = raw_user_details.transformed();
        match user_details.oauth_client {
            Some(oauth_client) => {
                let oauth_client_instance = initiate_auth_code_grant_flow(oauth_client).await;
                let redirect_url =
                    navigate_to_redirect_url(oauth_client_instance, ctx, oauth_client).await;
                Ok(AuthDetails {
                    url: Some(redirect_url),
                    token: None,
                })
            }
            None => {
                let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
                let db_query = format!(
                        "SELECT * FROM type::table($table) WHERE email = '{}' OR user_name = '{}' LIMIT 1",
                        &user_details.user_name.clone().unwrap(),
                        &user_details.user_name.clone().unwrap()
                    );

                let mut result = db.query(db_query).bind(("table", "user")).await?;
                // Get the first result from the first query
                let response: Option<User> = result.take(0)?;

                match &response {
                    Some(user) => {
                        let password_match = bcrypt::verify(
                            &user_details.password.unwrap(),
                            response.clone().unwrap().password.as_str(),
                        )
                        .unwrap();

                        if password_match {
                            let refresh_token_expiry_duration = Duration::from_secs(30 * 24 * 60 * 60); // minutes by 60 seconds
                            let key: Vec<u8>;
                            let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
                            let mut result = db.query("SELECT * FROM type::table($table) WHERE name = 'jwt_key' LIMIT 1")
                                .bind(("table", "crypto_key"))
                                .await?;
                            let response: Option<SymKey> = result.take(0)?;

                            match &response {
                                Some(key_container) => {
                                    key = key_container.key.clone();
                                }
                                None => {
                                    key = HS256Key::generate().to_bytes();
                                    let _reslt: Vec<SymKey> = db.create("crypto_key")
                                        .content(SymKey {
                                            key: key.clone(),
                                            name: "jwt_key".to_string(),
                                        })
                                        .await?;
                                }
                            }

                            let auth_claim = AuthClaim {
                                roles: user
                                    .roles
                                    .as_ref()
                                    .map(|t| t.iter().map(|t| t.id.to_raw()).collect())
                                    .unwrap_or(vec![]),
                            };

                            let converted_key = HS256Key::from_bytes(&key);

                            let mut token_claims = Claims::with_custom_claims(auth_claim.clone(), Duration::from_secs(15 * 60));
                            token_claims.subject = Some(user.id.as_ref().map(|t| &t.id).expect("id").to_raw());
                            let token_str = converted_key.authenticate(token_claims).unwrap();

                            let mut refresh_token_claims = Claims::with_custom_claims(auth_claim.clone(), refresh_token_expiry_duration);
                            refresh_token_claims.subject = Some(user.id.as_ref().map(|t| &t.id).expect("id").to_raw());
                            let refresh_token_str = converted_key.authenticate(refresh_token_claims).unwrap();

                            ctx.insert_http_header(SET_COOKIE, format!("oauth_client="));

                            ctx.append_http_header(
                                SET_COOKIE,
                                format!(
                                    "t={}; Max-Age={}",
                                    refresh_token_str,
                                    refresh_token_expiry_duration.as_secs()
                                ),
                            );
                            Ok(AuthDetails {
                                token: Some(token_str),
                                url: None,
                            })
                        } else {
                            Err(Error::new("Invalid username or password"))
                        }
                    }
                    None => Err(Error::new("Invalid username or password")),
                }
            }
        }
    }

    async fn sign_out(&self, ctx: &Context<'_>) -> Result<bool> {
        // Clear the refresh token cookie
        ctx.insert_http_header(SET_COOKIE, format!("t=; Max-Age=0"));
        Ok(true)
    }
}
