use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use hyper::{header::SET_COOKIE, HeaderMap};
use jwt_simple::prelude::*;
use lib::utils::auth::{AuthClaim, SymKey};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::{
        role::SystemRole,
        user::{
            AccountStatus, AuthDetails, SurrealRelationQueryResponse, User, UserLogins, UserUpdate,
        },
    },
    middleware::oauth::{
        confirm_auth, decode_token, get_user_id_from_token, initiate_auth_code_grant_flow,
        navigate_to_redirect_url,
    },
};

pub struct Mutation;

#[Object]
impl Mutation {
    async fn sign_up(&self, ctx: &Context<'_>, mut user: User) -> Result<User> {
        user.password = bcrypt::hash(user.password, bcrypt::DEFAULT_COST).unwrap();
        user.dob = match &user.dob {
            Some(ref date_str) => Some(
                chrono::DateTime::parse_from_rfc3339(date_str)
                    .unwrap()
                    .to_rfc3339(),
            ),
            None => None,
        };
        // chrono::DateTime::parse_from_rfc3339(&user.dob)
        // .unwrap()
        // .to_rfc3339();

        // User signup
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let response: User = db
            .create("user")
            .content(User {
                oauth_client: None,
                ..user
            })
            .await
            .map_err(|e| Error::new(e.to_string()))?
            .expect("Error creating user");

        Ok(response)
    }

    async fn create_user_role(
        &self,
        ctx: &Context<'_>,
        role: SystemRole,
    ) -> Result<Vec<SystemRole>> {
        let check_auth = confirm_auth(ctx).await;

        match check_auth {
            Ok(_) => {
                let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
                let response = db
                    .create("role")
                    .content(SystemRole { ..role })
                    .await
                    .map_err(|e| Error::new(e.to_string()))?
                    .expect("Error creating role");

                Ok(response)
            }
            _ => return Err(Error::new("Unauthorized")),
        }
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

                        if password_match && user.status == AccountStatus::Active {
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
                                    let _reslt: SymKey = db
                                        .create("crypto_key")
                                        .content(SymKey {
                                            key: key.clone(),
                                            name: "jwt_key".to_string(),
                                        })
                                        .await?
                                        .expect("Error creating key");
                                }
                            }

                            let get_user_roles_query = format!(
                                "SELECT ->has_role.out.* FROM user:{}",
                                user.id.as_ref().map(|t| &t.id).expect("id")
                            );
                            let mut user_roles_res = db.query(get_user_roles_query).await?;
                            let user_roles: Option<SurrealRelationQueryResponse<SystemRole>> =
                                user_roles_res.take(0)?;

                            let auth_claim = AuthClaim {
                                roles: match user_roles {
                                    Some(existing_roles) => {
                                        // use id instead of Thing
                                        existing_roles
                                            .get("->has_role")
                                            .unwrap()
                                            .get("out")
                                            .unwrap()
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

                            Ok(AuthDetails {
                                token: Some(token_str),
                                url: None,
                            })
                        } else {
                            Err(Error::new("Invalid username or password OR Unauthorized access(contact admin)."))
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

    async fn update_user(
        &self,
        ctx: &Context<'_>,
        mut user: UserUpdate,
        user_id: String,
    ) -> Result<User> {
        let check_auth = confirm_auth(ctx).await;

        match check_auth {
            Ok(_) => {
                let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

                let user_id_from_token = get_user_id_from_token(ctx).await.unwrap();

                if user_id_from_token != user_id {
                    return Err(Error::new("Unauthorized"));
                }

                if user.password.is_some() {
                    user.password =
                        Some(bcrypt::hash(user.password.unwrap(), bcrypt::DEFAULT_COST).unwrap());
                }

                let response: Option<User> = db
                    .update(("user", user_id.clone()))
                    .merge(user)
                    .await
                    .map_err(|e| Error::new(e.to_string()))?;

                match response {
                    Some(user) => Ok(user),
                    None => Err(Error::new("User not found")),
                }
            }
            _ => return Err(Error::new("Unauthorized")),
        }
    }

    pub async fn update_user_password(
        &self,
        ctx: &Context<'_>,
        user_id: String,
        new_password: String,
        mut user_info: UserUpdate,
    ) -> Result<User> {
        // no auth check just check old password against password entered by user
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let mut found_user_result = db
            .query("SELECT * FROM type::table($table) WHERE id = type::thing($user) LIMIT 1")
            .bind(("table", "user"))
            .bind(("user", format!("user:{}", user_id)))
            .await?;

        let found_user: Option<User> = found_user_result.take(0)?;

        match found_user {
            Some(user) => {
                let password_match = bcrypt::verify(
                    &user_info.password.unwrap().as_str(),
                    user.password.as_str(),
                )
                .unwrap();

                if password_match {
                    let new_password_hash =
                        bcrypt::hash(new_password, bcrypt::DEFAULT_COST).unwrap();
                    user_info.password = Some(new_password_hash);
                    let response: Option<User> = db
                        .update(("user", user_id.clone()))
                        .merge(user_info)
                        .await
                        .map_err(|e| Error::new(e.to_string()))?;

                    match response {
                        Some(user) => Ok(user),
                        None => Err(Error::new("User not found")),
                    }
                } else {
                    Err(Error::new("Verification failed"))
                }
            }
            None => Err(Error::new("User not found")),
        }

        // Ok(found_user)
    }
}
