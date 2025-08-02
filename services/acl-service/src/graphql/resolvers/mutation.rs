use std::{env, sync::Arc};

use async_graphql::{Context, Object, Result};
use axum::Extension;
use base64::{engine::general_purpose, Engine as _engine};
use hyper::{header::SET_COOKIE, HeaderMap, StatusCode};
use jwt_simple::prelude::*;
use lib::utils::{auth::AuthClaim, custom_error::ExtendedError, models::EmailMQTTPayload};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use rumqttc::v5::mqttbytes::QoS;
use surrealdb::{engine::remote::ws::Client, Surreal};
use tokio::fs;

use crate::{
    graphql::schemas::{
        role::{
            AdminPrivilege, AuthorizationConstraint, RoleInput, RoleMetadata, RoleType, SystemRole,
        },
        user::{AuthDetails, User, UserLogins, UserUpdate},
    },
    utils::{
        auth::{
            confirm_authentication, confirm_authorization, fetch_default_user_roles,
            initiate_auth_code_grant_flow, navigate_to_redirect_url, sign_jwt,
            verify_login_credentials,
        },
        user::create_user,
    },
    AppState,
};

pub struct Mutation;

#[Object]
impl Mutation {
    async fn sign_up(&self, ctx: &Context<'_>, mut user: User) -> Result<User> {
        user.password = bcrypt::hash(user.password, bcrypt::DEFAULT_COST).map_err(|e| {
            tracing::error!("Bcrypt Error: {}", e);
            ExtendedError::new("Failed to sign up", Some(StatusCode::BAD_REQUEST.as_u16())).build()
        })?;

        user.dob = match &user.dob {
            Some(ref date_str) => Some(
                (chrono::DateTime::parse_from_rfc3339(date_str).map_err(|e| {
                    tracing::error!("Parse from rfc3339 error: {}", e);
                    ExtendedError::new("Failed to sign up", Some(StatusCode::BAD_REQUEST.as_u16()))
                        .build()
                })?)
                .to_rfc3339(),
            ),
            None => None,
        };

        // User signup
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new(
                "Server Error",
                Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
            )
            .build()
        })?;

        let response: Option<User> = create_user(db, user).await.map_err(|e| {
            tracing::error!("Error creating user: {}", e);
            ExtendedError::new("Failed to sign up", Some(StatusCode::BAD_REQUEST.as_u16())).build()
        })?;

        match response {
            Some(user) => {
                let shared_state = ctx.data::<Extension<Arc<AppState>>>();

                // There should be a check to prevent any panics, especially because registration was successful
                if let Err(e) = &shared_state {
                    tracing::error!("Error extracting Shared State: {:?}", e);

                    return Ok(user);
                };

                let auth_claim = AuthClaim { roles: vec![] };
                let token_duration = Duration::from_secs(15 * 60); // minutes by 60 seconds;

                let user_id = user.id.as_ref().map(|t| &t.id).unwrap().to_raw();

                let signed_jwt = sign_jwt(&auth_claim, token_duration, &user_id).await;

                let public_key_path = env::var("RSA_PUBLIC_KEY_PATH");

                if let Err(e) = &public_key_path {
                    tracing::error!("Failed to get RSA_PUBLIC_KEY_PATH env var: {}", e);

                    return Ok(user);
                }

                let public_key = fs::read_to_string(&public_key_path.unwrap()).await;

                if let Err(e) = &signed_jwt {
                    tracing::error!("Failed to sign JWT: {}", e);

                    return Ok(user);
                }

                if let Err(e) = &public_key {
                    tracing::error!("Failed to read public key: {}", e);

                    return Ok(user);
                }

                let mut rng = rand::rngs::OsRng; // rand@0.8
                let public_key = RsaPublicKey::from_public_key_pem(&public_key.unwrap());

                if let Err(e) = &public_key {
                    tracing::error!("Failed to get public key: {}", e);

                    return Ok(user);
                }

                let encrypted_token = public_key.unwrap().encrypt(
                    &mut rng,
                    Pkcs1v15Encrypt,
                    &signed_jwt.unwrap().as_bytes(),
                );

                if let Err(e) = &encrypted_token {
                    tracing::error!("Failed to encrypt token: {}", e);

                    return Ok(user);
                }

                let auth_service = env::var("OAUTH_SERVICE");

                if let Err(e) = &auth_service {
                    tracing::error!("Failed to get OAUTH_SERVICE env var: {}", e);

                    return Ok(user);
                }

                let encoded_token =
                    general_purpose::URL_SAFE_NO_PAD.encode(&encrypted_token.unwrap()[..]);

                let verification_url = format!(
                    "{}/verify-email?token={}",
                    auth_service.unwrap(),
                    encoded_token
                );

                let email_template = format!(
                    r#"
                <div style="font-family: Arial, sans-serif; background-color: #f4f4f4;">
                    <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                        <h2 style="background-color: #4CAF50; color: #ffffff; padding: 10px; border-radius: 8px 8px 0 0; text-align: center;">Please Verify Your Email</h2>
                        <div style="padding: 10px;">
                            <p>Dear Customer,</p>
                            <p>We are pleased to inform you that you have successfully registered on our platform.</p>
                            <p>We just need to verify your email address. Please click the link below to confirm your email address.</p>
                            <p>
                                <a href="{}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">Verify Email</a>
                            </p>
                            <p>If you have any questions or concerns, please do not hesitate to contact our support team.</p>
                            <p>Thank you!</p>
                            <p>Sincerely,<br/>Elon A. Idiong'o<br />CEO</p>
                        </div>
                    </div>
                </div>
                "#,
                    verification_url
                );

                let email_payload = EmailMQTTPayload {
                    recipient: &user.email,
                    subject: "Email Address Verification",
                    title: "Verify Your Email Address",
                    template: email_template,
                };

                let encoded_payload = serde_json::to_vec(&email_payload);

                if let Err(e) = &encoded_payload {
                    tracing::error!("Error serializing Email Payload: {:?}", e);

                    return Ok(user);
                };

                if let Err(e) = shared_state
                    .unwrap()
                    .mqtt_client
                    .publish(
                        "email/send",
                        QoS::AtLeastOnce,
                        false,
                        encoded_payload.unwrap(),
                    )
                    .await
                {
                    tracing::error!("Failed to publish email/send event: {}", e);

                    return Ok(user);
                }
                Ok(user)
            }
            None => Err(ExtendedError::new(
                "Failed to sign up",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build()),
        }
    }

    async fn create_user_role(
        &self,
        ctx: &Context<'_>,
        role: RoleInput,
        role_metadata: RoleMetadata,
    ) -> Result<SystemRole> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new(
                "Server Error",
                Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
            )
            .build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        // TODO: Evaluate admin permissions here to restrict the Admin from giving Superadmin privileges. Constraint is already effected in the database.
        let authorization_constraint = if role_metadata.organization.is_some() {
            AuthorizationConstraint {
                roles: vec![],
                privilege: Some(AdminPrivilege::SuperAdmin),
            }
        } else {
            AuthorizationConstraint {
                roles: vec![],
                privilege: Some(AdminPrivilege::Admin),
            }
        };

        let authorized =
            confirm_authorization(db, &authenticated, authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new(
                "Unauthorized",
                Some(StatusCode::UNAUTHORIZED.as_u16()),
            )
            .build());
        }

        let is_admin = match role_metadata.role_type {
            RoleType::Admin => true,
            RoleType::Other => false,
        };

        if (role_metadata.department.is_some() && role_metadata.department_is_under.is_none())
            || (role_metadata.department.is_none() && role_metadata.department_is_under.is_some())
        {
            return Err(ExtendedError::new(
                "Invalid Input",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build());
        };

        let mut create_role_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);
                IF !$user.exists() {
                    THROW 'Invalid Input';
                };

                LET $created_role = (CREATE role CONTENT {
                    role_name: $role_input.role_name,
                    created_by: $user,
                    is_admin: type::bool($is_admin),
                    admin_permissions: $role_metadata.admin_permissions
                } RETURN AFTER);
                LET $role_id = (SELECT VALUE id FROM $created_role);
                IF $role_metadata.organization IS NOT NONE {
                    RELATE $role_id -> organization -> $role_id CONTENT {
                        org_name: $role_metadata.organization.org_name
                    };
                };

                IF $role_metadata.department IS NOT NONE {
                    IF $role_metadata.department_is_under.body = 'Organization' {
                        LET $org = type::thing('organization', $role_metadata.department_is_under.id);
                        IF !$org.exists() {
                            THROW 'Invalid Input';
                        };
                        LET $created_department = (SELECT VALUE id FROM (CREATE department CONTENT $role_metadata.department RETURN AFTER));
                        RELATE $created_department -> is_under -> $org;
                    } ELSE IF $role_metadata.department_is_under.body = 'Department' {
                        LET $dep = type::thing('department', $role_metadata.department_is_under.id);
                        IF !$dep.exists() {
                            THROW 'Invalid Input';
                        };
                        LET $created_department = (SELECT VALUE id FROM (CREATE department CONTENT $role_metadata.department RETURN AFTER));
                        RELATE $created_department -> is_under -> $dep;
                    } ELSE {
                        THROW 'Invalid Input';
                    };
                };

                RETURN $created_role;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("role_input", role))
            .bind(("role_metadata", role_metadata))
            .bind(("user_id", authenticated.sub.clone()))
            .bind(("is_admin", is_admin))
            .await
            .map_err(|e| {
                tracing::error!("Error creating role: {}", e);
                ExtendedError::new(
                    "Failed to create role",
                    Some(StatusCode::BAD_REQUEST.as_u16()),
                )
                .build()
            })?;

        let user_role: Option<SystemRole> = create_role_query.take(0).map_err(|e| {
            tracing::error!("Failed to create role: {}", e);
            ExtendedError::new(
                "Failed to create role",
                Some(StatusCode::BAD_REQUEST.as_u16()),
            )
            .build()
        })?;

        match user_role {
            Some(role) => Ok(role),
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
                let oauth_client_instance = initiate_auth_code_grant_flow(oauth_client).await?;
                let redirect_url =
                    navigate_to_redirect_url(oauth_client_instance, ctx, oauth_client).await;
                Ok(AuthDetails {
                    url: Some(redirect_url),
                    token: None,
                })
            }
            None => {
                let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
                    tracing::error!("Error extracting Surreal Client: {:?}", e);
                    ExtendedError::new(
                        "Server Error",
                        Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                    )
                    .build()
                })?;

                let verified_credentials = verify_login_credentials(db, &raw_user_details).await;

                match &verified_credentials {
                    Ok(user) => {
                        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
                            tracing::error!("Error extracting Surreal Client: {:?}", e);
                            ExtendedError::new(
                                "Server Error",
                                Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                            )
                            .build()
                        })?;

                        let refresh_token_expiry_duration = Duration::from_secs(30 * 24 * 60 * 60); // days by hours by minutes by 60 seconds
                        let access_token_expiry_duration = Duration::from_secs(15 * 60); // minutes by 60 seconds

                        let user_roles = fetch_default_user_roles(
                            db,
                            user.id
                                .clone()
                                .as_ref()
                                .map(|t| &t.id)
                                .unwrap()
                                .to_raw()
                                .as_str(),
                        )
                        .await?;

                        let auth_claim = AuthClaim { roles: user_roles };

                        let token_str = sign_jwt(
                            &auth_claim,
                            access_token_expiry_duration,
                            &user
                                .id
                                .as_ref()
                                .map(|t| &t.id)
                                .ok_or("Invalid ID")
                                .map_err(|e| {
                                    tracing::error!("{}", e);
                                    ExtendedError::new(
                                        "Forbidden",
                                        Some(StatusCode::FORBIDDEN.as_u16()),
                                    )
                                    .build()
                                })?
                                .to_raw(),
                        )
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to sign Access Token: {}", e);
                            ExtendedError::new(
                                "Internal Server Error",
                                Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                            )
                            .build()
                        })?;

                        let refresh_token_str = sign_jwt(
                            &auth_claim,
                            refresh_token_expiry_duration,
                            &user
                                .id
                                .as_ref()
                                .map(|t| &t.id)
                                .ok_or("Invalid ID")
                                .map_err(|e| {
                                    tracing::error!("{}", e);
                                    ExtendedError::new(
                                        "Forbidden",
                                        Some(StatusCode::FORBIDDEN.as_u16()),
                                    )
                                    .build()
                                })?
                                .to_raw(),
                        )
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
                    Err(e) => {
                        tracing::error!("Error signing in: {}", e);
                        Err(ExtendedError::new(
                            "Invalid credentials",
                            Some(StatusCode::UNAUTHORIZED.as_u16()),
                        )
                        .build())
                    }
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
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new(
                "Server Error",
                Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
            )
            .build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let check_auth = confirm_authentication(header_map, db).await?;

        if check_auth.sub != user_id {
            return Err(ExtendedError::new(
                "Unauthorized",
                Some(StatusCode::UNAUTHORIZED.as_u16()),
            )
            .build());
        }

        if user.password.is_some() {
            user.password = Some(
                bcrypt::hash(user.password.unwrap(), bcrypt::DEFAULT_COST).map_err(|e| {
                    tracing::error!("Bcrypt Error: {}", e);
                    ExtendedError::new("Failed to sign up", Some(StatusCode::BAD_REQUEST.as_u16()))
                        .build()
                })?,
            );
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
