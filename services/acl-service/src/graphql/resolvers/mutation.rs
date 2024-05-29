use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use hyper::{header::SET_COOKIE, HeaderMap};
use jwt_simple::prelude::*;
use lib::utils::auth::{AuthClaim, SymKey};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    middleware::oauth::{decode_token, initiate_auth_code_grant_flow, navigate_to_redirect_url},
    graphql::schemas::{
        role::SystemRole,
        user::{AuthDetails, SurrealRelationQueryResponse, User, UserLogins},
    },
};

pub struct Mutation;

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
                            let refresh_token_expiry_duration =
                                Duration::from_secs(30 * 24 * 60 * 60); // minutes by 60 seconds
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
                                    let _reslt: Vec<SymKey> = db
                                        .create("crypto_key")
                                        .content(SymKey {
                                            key: key.clone(),
                                            name: "jwt_key".to_string(),
                                        })
                                        .await?;
                                }
                            }

                            let get_user_roles_query = format!(
                                "SELECT ->has_role.out.* FROM user:{}",
                                user.id.as_ref().map(|t| &t.id).expect("id")
                            );
                            let mut user_roles_res = db.query(get_user_roles_query).await?;
                            let user_roles: Option<SurrealRelationQueryResponse<SystemRole>> =
                                user_roles_res.take(0)?;
                            println!("user_roles: {:?}", user_roles);

                            let auth_claim = AuthClaim {
                                roles: match user_roles {
                                    Some(existing_roles) => {
                                        // use id instead of Thing
                                        existing_roles
                                            .get("->has_role")
                                            .unwrap()
                                            .get("out")
                                            .unwrap()
                                            // existing_roles["->has_role"]["out"]
                                            .into_iter()
                                            .map(|role| {
                                                role.id
                                                    .as_ref()
                                                    .map(|t| &t.id)
                                                    .expect("id")
                                                    .to_raw()
                                            })
                                            .collect()
                                    }
                                    None => vec![],
                                },
                            };

                            let converted_key = HS256Key::from_bytes(&key);

                            let mut token_claims = Claims::with_custom_claims(
                                auth_claim.clone(),
                                Duration::from_secs(15 * 60),
                            );
                            token_claims.subject =
                                Some(user.id.as_ref().map(|t| &t.id).expect("id").to_raw());
                            let token_str = converted_key.authenticate(token_claims).unwrap();

                            let mut refresh_token_claims = Claims::with_custom_claims(
                                auth_claim.clone(),
                                refresh_token_expiry_duration,
                            );
                            refresh_token_claims.subject =
                                Some(user.id.as_ref().map(|t| &t.id).expect("id").to_raw());
                            let refresh_token_str =
                                converted_key.authenticate(refresh_token_claims).unwrap();

                            match ctx.data_opt::<HeaderMap>() {
                                Some(headers) => {
                                    // Check if Host header is present
                                    let mut g_host: String = "127.0.0.1".to_string();
                                    match headers.get("Origin") {
                                        Some(host) => {
                                            // g_host = host.to_str().unwrap().to_string();
                                            // remove http:// or https:// and port(:port_number)
                                            g_host = host
                                                .to_str()
                                                .unwrap()
                                                .split("//")
                                                .collect::<Vec<&str>>()[1]
                                                .split(":")
                                                .collect::<Vec<&str>>()[0]
                                                .to_string();
                                        }
                                        None => {}
                                    }

                                    ctx.insert_http_header(
                                        SET_COOKIE,
                                        format!(
                                            "oauth_client=; SameSite=None; Secure; Domain={}; HttpOnly; Path=/",
                                            g_host.as_str()
                                        ),
                                    );

                                    ctx.append_http_header(
                                        SET_COOKIE,
                                        format!(
                                            "t={}; Max-Age={}; SameSite=None; Secure; Domain={}; HttpOnly; Path=/",
                                            refresh_token_str,
                                            refresh_token_expiry_duration.as_secs(),
                                            g_host.as_str()
                                        ),
                                    );
                                }
                                None => {}
                            }

                            // ctx.insert_http_header(
                            //     SET_COOKIE,
                            //     format!(
                            //         "oauth_client=; SameSite=None; Secure=False; Path=/; Domain={}",
                            //         ctx.http_header("Host").unwrap_or("127.0.0.1")
                            //     ),
                            // );

                            println!("header exists: {}", ctx.http_header_contains(SET_COOKIE));

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

    async fn decode_token(&self, ctx: &Context<'_>) -> Result<String> {
        match ctx.data_opt::<HeaderMap>() {
            Some(headers) => {
                let token_claims = decode_token(ctx, headers.get("Authorization").unwrap()).await;

                match token_claims {
                    Ok(token_claims) => Ok(token_claims.subject.unwrap()),
                    Err(e) => Err(e),
                }
            }
            None => Err(Error::new("No headers found")),
        }
    }
}
