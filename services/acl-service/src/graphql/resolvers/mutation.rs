use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use hyper::{header::SET_COOKIE, HeaderMap};
use jwt_simple::prelude::*;
use lib::utils::auth::AuthClaim;
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::{
        role::SystemRole,
        user::{AuthDetails, SurrealRelationQueryResponse, User, UserLogins, UserUpdate},
    },
    utils::auth::{
        confirm_auth, decode_token, get_user_id_from_token, initiate_auth_code_grant_flow,
        navigate_to_redirect_url, sign_jwt, verify_login_credentials,
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

                let verified_credentials = verify_login_credentials(db, &raw_user_details).await;

                match &verified_credentials {
                    Ok(user) => {
                        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

                        let refresh_token_expiry_duration = Duration::from_secs(30 * 24 * 60 * 60); // days by hours by minutes by 60 seconds
                        let access_token_expiry_duration = Duration::from_secs(15 * 60); // minutes by 60 seconds

                        let mut user_roles_res = db
                            .query(
                                "
                            SELECT ->has_role->role.* AS roles FROM ONLY type::thing($user_id)
                            ",
                            )
                            .bind((
                                "user_id",
                                format!("user:{}", user.id.as_ref().map(|t| &t.id).expect("id")),
                            ))
                            .await
                            .map_err(|_e| Error::new("DB Query failed: Get Roles"))?;
                        let user_roles: Option<SurrealRelationQueryResponse<SystemRole>> =
                            user_roles_res
                                .take(0)
                                .map_err(|e| Error::new(e.to_string()))?;

                        let auth_claim = AuthClaim {
                            roles: match user_roles {
                                Some(existing_roles) => {
                                    // use id instead of Thing
                                    existing_roles
                                        .get("roles")
                                        .unwrap()
                                        .into_iter()
                                        .map(|role| {
                                            role.id.as_ref().map(|t| &t.id).expect("id").to_raw()
                                        })
                                        .collect()
                                }
                                None => vec![],
                            },
                        };

                        let token_str =
                            sign_jwt(db, &auth_claim, access_token_expiry_duration, user)
                                .await
                                .map_err(|_e| Error::new("DB Query failed"))?;

                        let refresh_token_str =
                            sign_jwt(db, &auth_claim, refresh_token_expiry_duration, user)
                                .await
                                .map_err(|_e| Error::new("DB Query failed"))?;

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
                                        "oauth_client=; SameSite=Strict; Secure; Domain={}; HttpOnly; Path=/",
                                        g_host.as_str()
                                    ),
                                );

                                ctx.append_http_header(
                                    SET_COOKIE,
                                    format!(
                                        "t={}; Max-Age={}; SameSite=Strict; Secure; Domain={}; HttpOnly; Path=/",
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
                    }
                    Err(_e) => Err(Error::new("Invalid username or password")),
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
                let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

                let token_claims = decode_token(db, headers.get("Authorization").unwrap()).await;

                match token_claims {
                    Ok(token_claims) => Ok(token_claims.subject.unwrap()),
                    Err(e) => Err(e.into()),
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
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        let found_user: Option<User> = found_user_result
            .take(0)
            .map_err(|_e| Error::new("Deserialization failed"))?;

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
    }
}
