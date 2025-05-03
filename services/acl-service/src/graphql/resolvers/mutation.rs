use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use hyper::{header::SET_COOKIE, HeaderMap, StatusCode};
use jwt_simple::prelude::*;
use lib::utils::{auth::AuthClaim, custom_error::ExtendedError};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::{
        role::SystemRole,
        user::{AuthDetails, SurrealRelationQueryResponse, User, UserLogins, UserUpdate},
    },
    utils::auth::{
        confirm_auth, initiate_auth_code_grant_flow, navigate_to_redirect_url, sign_jwt,
        verify_login_credentials,
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

        let response: Option<User> = db
            .create("user")
            .content(User {
                oauth_client: None,
                ..user
            })
            .await
            .map_err(|e| {
                tracing::error!("Error creating user: {}", e);
                ExtendedError::new("Failed to sign up", Some(StatusCode::BAD_REQUEST.as_u16()))
                    .build()
            })?;

        match response {
            Some(user) => Ok(user),
            None => Err(ExtendedError::new(
                "Failed to sign up",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build()),
        }
    }

    async fn create_user_role(&self, ctx: &Context<'_>, role: SystemRole) -> Result<SystemRole> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
        let header_map = ctx.data_opt::<HeaderMap>();

        let check_auth = confirm_auth(header_map, db).await;

        if let Err(e) = check_auth {
            tracing::error!("Unauthorized: {}", e);
            return Err(ExtendedError::new(
                "Unauthorized",
                Some(StatusCode::UNAUTHORIZED.as_u16()),
            )
            .build());
        }

        let response: Option<SystemRole> = db
            .create("role")
            .content(SystemRole { ..role })
            .await
            .map_err(|e| {
            tracing::error!("Error creating role: {}", e);
            ExtendedError::new(
                "Failed to create role",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build()
        })?;

        match response {
            Some(user) => Ok(user),
            None => Err(ExtendedError::new(
                "Failed to create role",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build()),
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
                                SELECT ->(has_role WHERE is_default=true)->role.* AS roles FROM ONLY type::thing($user_id)
                            ",
                            )
                            .bind(("user_id", user.id.clone()))
                            .await
                            .map_err(|_e| Error::new("DB Query failed: Get Roles"))?;
                        let user_roles: Option<SurrealRelationQueryResponse<SystemRole>> =
                            user_roles_res.take(0).map_err(|e| {
                                tracing::error!("Failed to get roles: {}", e);
                                ExtendedError::new(
                                    "Failed to get roles",
                                    Some(StatusCode::BAD_REQUEST.as_u16()),
                                )
                                .build()
                            })?;

                        let auth_claim = AuthClaim {
                            roles: match user_roles {
                                Some(existing_roles) => {
                                    // use id instead of Thing
                                    existing_roles
                                        .get("roles")
                                        .unwrap()
                                        .into_iter()
                                        .map(|role| {
                                            let name_str = format!("{:?}", role.role_name);
                                            tracing::debug!("name_str: {}", name_str);
                                            name_str
                                        })
                                        .collect()
                                }
                                None => {
                                    return Err(ExtendedError::new(
                                        "Forbidden!",
                                        Some(StatusCode::FORBIDDEN.as_u16()),
                                    )
                                    .build())
                                }
                            },
                        };

                        let token_str = sign_jwt(&auth_claim, access_token_expiry_duration, user)
                            .await
                            .map_err(|e| {
                                tracing::error!("Failed to sign Access Token: {}", e);
                                ExtendedError::new(
                                    "Internal Server Error",
                                    Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                                )
                                .build()
                            })?;

                        let refresh_token_str =
                            sign_jwt(&auth_claim, refresh_token_expiry_duration, user)
                                .await
                                .map_err(|e| {
                                    tracing::error!("Failed to sign Refresh Token: {}", e);
                                    ExtendedError::new(
                                        "Internal Server Error",
                                        Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                                    )
                                    .build()
                                })?;

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
                    Err(_e) => Err(ExtendedError::new(
                        "Invalid credentials",
                        Some(StatusCode::UNAUTHORIZED.as_u16()),
                    )
                    .build()),
                }
            }
        }
    }

    async fn sign_out(&self, ctx: &Context<'_>) -> Result<bool> {
        // Clear the refresh token cookie
        ctx.insert_http_header(SET_COOKIE, format!("t=; Max-Age=0"));
        Ok(true)
    }

    async fn update_user(
        &self,
        ctx: &Context<'_>,
        mut user: UserUpdate,
        user_id: String,
    ) -> Result<User> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();
        let header_map = ctx.data_opt::<HeaderMap>();

        let check_auth = confirm_auth(header_map, db).await?;

        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        if check_auth.sub != user_id {
            return Err(ExtendedError::new(
                "Unauthorized",
                Some(StatusCode::UNAUTHORIZED.as_u16()),
            )
            .build());
        }

        if user.password.is_some() {
            user.password =
                Some(bcrypt::hash(user.password.unwrap(), bcrypt::DEFAULT_COST).unwrap());
        }

        let response: Option<User> = db
            .update(("user", user_id.clone()))
            .merge(user)
            .await
            .map_err(|e| {
                tracing::debug!("Failed to update user: {}", e);
                ExtendedError::new(
                    "Failed to update user",
                    Some(StatusCode::BAD_REQUEST.as_u16()),
                )
                .build()
            })?;

        match response {
            Some(user) => Ok(user),
            None => Err(
                ExtendedError::new("User not found", Some(StatusCode::NOT_FOUND.as_u16())).build(),
            ),
        }
    }
}
