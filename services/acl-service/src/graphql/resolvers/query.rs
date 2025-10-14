use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use hyper::{
    header::{AUTHORIZATION, COOKIE},
    HeaderMap, StatusCode,
};
use lib::utils::{
    custom_error::ExtendedError,
    models::{AdminPrivilege, AuthStatus, AuthorizationConstraint},
};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::{role::SystemRole, user::User},
    utils::auth::{confirm_authentication, confirm_authorization},
};

pub struct Query;

#[Object]
impl Query {
    async fn fetch_all_users(&self, ctx: &Context<'_>) -> Result<Vec<User>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            roles: vec![],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, &authenticated, authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let response: Vec<User> = db.select("user").await.map_err(|e| {
            tracing::error!("Error fetching users: {}", e);
            ExtendedError::new("Error fetching users", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        Ok(response)
    }

    async fn fetch_single_user(&self, ctx: &Context<'_>, user_id: String) -> Result<User> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        match ctx.data_opt::<HeaderMap>() {
            Some(header_map) => {
                let auth_header = header_map.get(AUTHORIZATION);
                let cookie_header = header_map.get(COOKIE);

                if auth_header.is_none() || cookie_header.is_none() {
                    let mut user_query = db
                        .query(
                            "
                            BEGIN TRANSACTION;
                            LET $user_id = type::thing('user', $user_id);
                            LET $user = (SELECT id, first_name, middle_name, last_name, full_name, dob, email, country, profile_picture, bio, website, address FROM ONLY $user_id LIMIT 1);
                            RETURN $user;
                            COMMIT TRANSACTION;
                            "
                        )
                        .bind(("user_id", user_id))
                        .await
                        .map_err(|e| {
                        tracing::error!("Error fetching user: {}", e);
                        ExtendedError::new("Error fetching user", StatusCode::BAD_REQUEST.as_str()).build()
                    })?;

                    let user: Option<User> = user_query.take(0).map_err(|e| {
                        tracing::debug!("User deserialization error: {}", e);
                        ExtendedError::new(
                            "Server Error",
                            StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                        )
                        .build()
                    })?;

                    match user {
                        Some(user) => return Ok(user),
                        None => {
                            return Err(ExtendedError::new(
                                "User not found",
                                StatusCode::NOT_FOUND.as_str(),
                            )
                            .build())
                        }
                    }
                }

                let authenticated = confirm_authentication(Some(header_map), db).await?;

                let authorization_constraint = AuthorizationConstraint {
                    roles: vec![],
                    privilege: Some(AdminPrivilege::Admin),
                };

                let authorized =
                    confirm_authorization(db, &authenticated, authorization_constraint).await?;

                if !authorized && authenticated.sub != user_id {
                    return Err(
                        ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                    );
                }

                let user: Option<User> = db.select(("user", user_id)).await.map_err(|e| {
                    tracing::error!("Error fetching user: {}", e);
                    ExtendedError::new("Error fetching user", StatusCode::BAD_REQUEST.as_str())
                        .build()
                })?;

                match user {
                    Some(user) => Ok(user),
                    None => Err(ExtendedError::new(
                        "User not found",
                        StatusCode::NOT_FOUND.as_str(),
                    )
                    .build()),
                }
            }
            None => {
                tracing::error!("Malformed request!");
                return Err(ExtendedError::new(
                    "Malformed request",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build());
            }
        }
    }

    async fn check_auth(&self, ctx: &Context<'_>) -> Result<AuthStatus> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        confirm_authentication(header_map, db)
            .await
            .map_err(Error::from)
    }

    async fn fetch_system_roles(
        &self,
        ctx: &Context<'_>,
        user_id: Option<String>,
    ) -> Result<Vec<SystemRole>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            roles: vec![],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, &authenticated, authorization_constraint).await?;

        if user_id.is_none() {
            if !authorized {
                return Err(
                    ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                );
            }

            let response: Vec<SystemRole> = db.select("role").await.map_err(|e| {
                tracing::error!("Error fetching roles: {}", e);
                ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

            Ok(response)
        } else {
            let user_id = user_id.unwrap();
            if user_id != authenticated.sub && !authorized {
                return Err(
                    ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                );
            }

            let mut fetch_user_roles_query = db
                .query(
                    "
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);

                IF !$user.exists() {
                    THROW 'Invalid Input';
                };
                LET $roles = (SELECT ->assigned->role.* AS roles FROM ONLY $user)['roles'];
                RETURN $roles;
                COMMIT TRANSACTION;
                ",
                )
                .bind(("user_id", user_id))
                .await
                .map_err(|e| {
                    tracing::error!("Error fetching roles: {}", e);
                    ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str())
                        .build()
                })?;

            let response: Vec<SystemRole> = fetch_user_roles_query.take(0).map_err(|e| {
                tracing::debug!("SystemRole deserialization error: {}", e);
                ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                    .build()
            })?;

            Ok(response)
        }
    }
}
