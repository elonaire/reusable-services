use std::{env, sync::Arc};

use async_graphql::{Context, Object, Result};
use axum::Extension;
use base64::{engine::general_purpose, Engine as _engine};
use hyper::{
    header::{COOKIE, SET_COOKIE},
    HeaderMap, StatusCode,
};
use jwt_simple::prelude::*;
use lib::utils::{
    auth::AuthClaim,
    cookie_parser::parse_cookies,
    custom_error::ExtendedError,
    models::{AdminPrivilege, AuthorizationConstraint, EmailMQTTPayload, RoleType},
};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use rumqttc::v5::mqttbytes::QoS;
use surrealdb::{engine::remote::ws::Client, Surreal};
use tokio::fs;

use crate::{
    graphql::schemas::{
        role::{
            Department, DepartmentInput, DepartmentInputMetadata, Organization, OrganizationInput,
            Permission, PermissionInput, Resource, ResourceInput, ResourceMetadata, RoleInput,
            RoleMetadata, SystemRole,
        },
        user::{AuthDetails, User, UserInput, UserLogins, UserUpdate},
    },
    utils::{
        auth::{
            confirm_authentication, confirm_authorization, fetch_user_roles,
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
    /// User signup
    async fn sign_up(&self, ctx: &Context<'_>, mut user: UserInput) -> Result<User> {
        user.password = bcrypt::hash(user.password, bcrypt::DEFAULT_COST).map_err(|e| {
            tracing::error!("Bcrypt Error: {}", e);
            ExtendedError::new("Failed to sign up", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        user.dob = match &user.dob {
            Some(ref date_str) => Some(
                (chrono::DateTime::parse_from_rfc3339(date_str).map_err(|e| {
                    tracing::error!("Parse from rfc3339 error: {}", e);
                    ExtendedError::new("Failed to sign up", StatusCode::BAD_REQUEST.as_str())
                        .build()
                })?)
                .to_rfc3339(),
            ),
            None => None,
        };

        // User signup
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let response: Option<User> = create_user(db, user).await.map_err(|e| {
            tracing::error!("Error creating user: {}", e);
            ExtendedError::new("Failed to sign up", StatusCode::BAD_REQUEST.as_str()).build()
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

                let user_id = user.id.key().to_string();

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
            None => Err(
                ExtendedError::new("Failed to sign up", StatusCode::BAD_REQUEST.as_str()).build(),
            ),
        }
    }

    /// Create system role
    async fn create_system_role(
        &self,
        ctx: &Context<'_>,
        mut role_input: RoleInput,
        role_metadata: RoleMetadata,
    ) -> Result<SystemRole> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authenticated_ref = &authenticated;

        // Evaluate admin permissions here to restrict the Admin from giving Superadmin privileges. Constraint is already effected in the database.
        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:role".into()],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, authenticated_ref, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let is_admin = match role_metadata.role_type {
            RoleType::Admin => true,
            RoleType::Other => false,
        };

        role_input.created_by = format!("user:{}", authenticated_ref.sub);
        role_input.is_admin = is_admin;

        let mut create_role_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);
                IF !$user.exists() {
                    THROW 'Invalid Input: User not found!';
                };

                IF ($role_metadata.organization_id IS NONE AND $role_metadata.department_id IS NONE) OR ($role_metadata.organization_id IS NOT NONE AND $role_metadata.department_id IS NOT NONE) {
                    THROW 'Invalid Input: Check organization_id and/or department_id!';
                };

                LET $created_role = (CREATE role CONTENT $role_input RETURN AFTER);
                LET $role_record_id = (SELECT VALUE id FROM $created_role);
                FOR $permission_id IN $role_metadata.permission_ids {
                    LET $permission = type::thing('permission', $permission_id);
                    IF !$permission.exists() {
                        THROW 'Invalid Input: Permission not found!';
                    };
                    LET $permission_is_admin = (SELECT VALUE is_admin FROM ONLY $permission);

                    IF $permission_is_admin AND !$role_input.is_admin {
                        THROW 'Invalid Input: An admin permission cannot be granted to a non-admin user!';
                    };

                    RELATE $role_record_id -> granted -> $permission;
                };
                IF $role_metadata.organization_id IS NOT NONE {
                    LET $organization = type::thing('organization', $role_metadata.organization_id);
                    IF !$organization.exists() {
                        THROW 'Invalid Input: Organization not found!';
                    };
                    RELATE $role_record_id -> is_under -> $organization;
                };

                IF $role_metadata.department_id IS NOT NONE {
                    LET $department = type::thing('department', $role_metadata.department_id);
                    IF !$department.exists() {
                        THROW 'Invalid Input: Department not found!';
                    };
                    RELATE $role_record_id -> is_under -> $department;
                };

                RETURN $created_role;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("role_input", role_input))
            .bind(("role_metadata", role_metadata))
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .bind(("is_admin", is_admin))
            .await
            .map_err(|e| {
                tracing::error!("Error creating role: {}", e);
                ExtendedError::new("Failed to create role", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let user_role: Option<SystemRole> = create_role_query.take(0).map_err(|e| {
            tracing::error!("Failed to create role: {}", e);
            ExtendedError::new("Failed to create role", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        match user_role {
            Some(role) => Ok(role),
            None => Err(ExtendedError::new(
                "Failed to create role",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// User signin
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
                    ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                        .build()
                })?;

                let verified_credentials = verify_login_credentials(db, &raw_user_details).await;

                match &verified_credentials {
                    Ok(user) => {
                        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
                            tracing::error!("Error extracting Surreal Client: {:?}", e);
                            ExtendedError::new(
                                "Server Error",
                                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                            )
                            .build()
                        })?;

                        let refresh_token_expiry_duration = Duration::from_secs(30 * 24 * 60 * 60); // days by hours by minutes by 60 seconds
                        let access_token_expiry_duration = Duration::from_secs(15 * 60); // minutes by 60 seconds

                        let user_roles =
                            fetch_user_roles(db, &user.id.key().to_string(), None).await?;

                        let auth_claim = AuthClaim { roles: user_roles };

                        let token_str = sign_jwt(
                            &auth_claim,
                            access_token_expiry_duration,
                            &user.id.key().to_string(),
                        )
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to sign Access Token: {}", e);
                            ExtendedError::new(
                                "Internal Server Error",
                                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                            )
                            .build()
                        })?;

                        let refresh_token_str = sign_jwt(
                            &auth_claim,
                            refresh_token_expiry_duration,
                            &user.id.key().to_string(),
                        )
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to sign Refresh Token: {}", e);
                            ExtendedError::new(
                                "Internal Server Error",
                                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                            )
                            .build()
                        })?;

                        match ctx.data_opt::<HeaderMap>() {
                            Some(headers) => {
                                // Check if Host header is present
                                let g_host = match headers.get("Origin") {
                                    Some(host) => {
                                        // remove http:// or https:// and port(:port_number)
                                        host.to_str().unwrap().split("//").collect::<Vec<&str>>()[1]
                                            .split(":")
                                            .collect::<Vec<&str>>()[0]
                                    }
                                    None => "127.0.0.1",
                                };

                                ctx.insert_http_header(
                                    SET_COOKIE,
                                    format!(
                                        "oauth_client=; SameSite=Strict; Secure; Domain={}; HttpOnly; Path=/",
                                        g_host
                                    ),
                                );

                                ctx.append_http_header(
                                    SET_COOKIE,
                                    format!(
                                        "t={}; Max-Age={}; SameSite=Strict; Secure; Domain={}; HttpOnly; Path=/",
                                        refresh_token_str,
                                        refresh_token_expiry_duration.as_secs(),
                                        g_host
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
                            StatusCode::UNAUTHORIZED.as_str(),
                        )
                        .build())
                    }
                }
            }
        }
    }

    /// Sign out
    async fn sign_out(&self, ctx: &Context<'_>) -> Result<bool> {
        // Clear the refresh token cookie
        ctx.insert_http_header(SET_COOKIE, format!("t=; Max-Age=0"));
        Ok(true)
    }

    /// Update user details
    async fn update_user(&self, ctx: &Context<'_>, mut user: UserUpdate) -> Result<User> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authenticated_ref = &authenticated;

        // Evaluate admin permissions here to restrict the Admin from giving Superadmin privileges. Constraint is already effected in the database.
        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:user".into()],
            privilege: None,
        };

        let authorized =
            confirm_authorization(db, authenticated_ref, &authorization_constraint).await?;
        let user_ref = &mut user;

        if user_ref.id.is_none() {
            tracing::error!("User ID was not provided in request body!");
            return Err(
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build(),
            );
        }

        let user_id = user_ref.id.as_ref().unwrap().to_owned();
        user_ref.id = None;

        if authenticated_ref.sub != user_id && !authorized {
            tracing::error!("User is neither admin nor resource owner!");
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        if user_ref.password.is_some() {
            user_ref.password = Some(
                bcrypt::hash(user_ref.password.as_ref().unwrap(), bcrypt::DEFAULT_COST).map_err(
                    |e| {
                        tracing::error!("Bcrypt Error: {}", e);
                        ExtendedError::new("Failed to sign up", StatusCode::BAD_REQUEST.as_str())
                            .build()
                    },
                )?,
            );
        }

        let response: Option<User> = db
            .update(("user", user_id.clone()))
            .merge(user)
            .await
            .map_err(|e| {
                tracing::error!("Failed to update user: {}", e);
                ExtendedError::new("Failed to update user", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        match response {
            Some(user) => Ok(user),
            None => {
                Err(ExtendedError::new("User not found", StatusCode::NOT_FOUND.as_str()).build())
            }
        }
    }

    /// Assign a role to a user
    async fn assign_system_role(
        &self,
        ctx: &Context<'_>,
        role_id: String,
        user_id: String,
    ) -> Result<SystemRole> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["assign:role".into()],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, &authenticated, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut assign_role_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $role = type::thing('role', $role_id);
                LET $user = type::thing('user', $user_id);
                LET $role_creator = (SELECT VALUE created_by FROM ONLY $role LIMIT 1);

                IF !$role.exists() OR !$user.exists() {
                    THROW 'Invalid Input';
                };

                LET $role_is_under_user_org = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(organization WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(organization WHERE created_by = $user))) > 0;
               	LET $role_is_under_user_dep = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(department WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(department WHERE created_by = $user))) > 0;

                IF $role_creator != $user AND !$role_is_under_user_org AND !$role_is_under_user_dep {
                    THROW 'Forbidden!';
                };

                RELATE $user->assigned->$role CONTENT {
                  is_default: false
                };

                LET $role = SELECT * FROM ONLY $role LIMIT 1;
                RETURN $role;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("role_id", role_id))
            .bind(("user_id", user_id))
            .await
            .map_err(|e| {
                tracing::error!("Error assigning role: {}", e);
                ExtendedError::new("Failed to assign role", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let user_role: Option<SystemRole> = assign_role_query.take(0).map_err(|e| {
            tracing::error!("Failed to assign role: {}", e);
            ExtendedError::new("Failed to assign role", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        match user_role {
            Some(role) => Ok(role),
            None => Err(ExtendedError::new(
                "Failed to assign role",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Assign a role to a user
    async fn revoke_system_role(
        &self,
        ctx: &Context<'_>,
        role_id: String,
        user_id: String,
    ) -> Result<SystemRole> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["revoke:role".into()],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, &authenticated, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut assign_role_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $role = type::thing('role', $role_id);
                LET $user = type::thing('user', $user_id);
                LET $role_creator = (SELECT VALUE created_by FROM ONLY $role LIMIT 1);

                IF !$role.exists() OR !$user.exists() {
                    THROW 'Invalid Input';
                };

                LET $role_is_under_user_org = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(organization WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(organization WHERE created_by = $user))) > 0;
               	LET $role_is_under_user_dep = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(department WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(department WHERE created_by = $user))) > 0;

                IF $role_creator != $user AND !$role_is_under_user_org AND !$role_is_under_user_dep {
                    THROW 'Forbidden!';
                };

                DELETE $user->assigned WHERE out = $role;

                LET $role = SELECT * FROM ONLY $role LIMIT 1;
                RETURN $role;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("role_id", role_id))
            .bind(("user_id", user_id))
            .await
            .map_err(|e| {
                tracing::error!("Error assigning role: {}", e);
                ExtendedError::new("Failed to assign role", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let user_role: Option<SystemRole> = assign_role_query.take(0).map_err(|e| {
            tracing::error!("Failed to assign role: {}", e);
            ExtendedError::new("Failed to assign role", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        match user_role {
            Some(role) => Ok(role),
            None => Err(ExtendedError::new(
                "Failed to assign role",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Create organization
    async fn create_organization(
        &self,
        ctx: &Context<'_>,
        mut organization_input: OrganizationInput,
    ) -> Result<Organization> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:organization".into()],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authenticated_ref = &authenticated;

        let authorized =
            confirm_authorization(db, authenticated_ref, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        organization_input.created_by = format!("user:{}", authenticated_ref.sub);

        let mut create_organization_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $organization = (SELECT * FROM ONLY (CREATE organization CONTENT $organization_input) LIMIT 1);

                RETURN $organization;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("organization_input", organization_input))
            .await
            .map_err(|e| {
                tracing::error!("Error creating organization: {}", e);
                ExtendedError::new(
                    "Failed to create organization",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        let organization_response: Option<Organization> =
            create_organization_query.take(0).map_err(|e| {
                tracing::error!("Failed to create organization: {}", e);
                ExtendedError::new(
                    "Failed to create organization",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        match organization_response {
            Some(organization) => Ok(organization),
            None => Err(ExtendedError::new(
                "Failed to create organization",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Create department
    async fn create_department(
        &self,
        ctx: &Context<'_>,
        mut department_input: DepartmentInput,
        department_input_metadata: DepartmentInputMetadata,
    ) -> Result<Department> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:department".into()],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authenticated_ref = &authenticated;

        let authorized =
            confirm_authorization(db, authenticated_ref, &authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        department_input.created_by = format!("user:{}", authenticated_ref.sub);

        let mut create_department_query = db
            .query(
                "
                BEGIN TRANSACTION;
                IF $department_input_metadata.organization_id {
                    LET $org = type::thing('organization', $department_input_metadata.organization_id);
                    IF !$org.exists() {
                        THROW 'Invalid Input';
                    };
                    LET $created_department = (CREATE department CONTENT $department_input RETURN AFTER);
                    LET $department_id = (SELECT VALUE id FROM ONLY $created_department LIMIT 1);
                    RELATE $department_id -> is_under -> $org;

                    RETURN $created_department;
                } ELSE IF $department_input_metadata.department_id {
                    LET $dep = type::thing('department', $department_input_metadata.department_id);
                    IF !$dep.exists() {
                        THROW 'Invalid Input';
                    };
                    LET $created_department = (CREATE department CONTENT $department_input RETURN AFTER);
                    LET $department_id = (SELECT VALUE id FROM ONLY $created_department LIMIT 1);
                    RELATE $department_id -> is_under -> $dep;

                    RETURN $created_department;
                } ELSE {
                    THROW 'Invalid Input';
                };

                COMMIT TRANSACTION;
                ",
            )
            .bind(("department_input", department_input))
            .bind(("department_input_metadata", department_input_metadata))
            .await
            .map_err(|e| {
                tracing::error!("Error creating department: {}", e);
                ExtendedError::new(
                    "Failed to create department",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        let department_response: Option<Department> =
            create_department_query.take(0).map_err(|e| {
                tracing::error!("Failed to create department: {}", e);
                ExtendedError::new(
                    "Failed to create department",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        match department_response {
            Some(department) => Ok(department),
            None => Err(ExtendedError::new(
                "Failed to create department",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Switch user role
    async fn switch_role(&self, ctx: &Context<'_>, role_id: String) -> Result<AuthDetails> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authenticated_ref = &authenticated;

        match header_map {
            Some(headers) => {
                match headers.get(COOKIE) {
                    Some(cookie_header) => {
                        let cookies_str = cookie_header.to_str().map_err(|e| {
                            tracing::error!("Error parsing cookie header: {}", e);
                            ExtendedError::new(
                                "Malformed request",
                                StatusCode::BAD_REQUEST.as_str(),
                            )
                            .build()
                        })?;
                        let cookies = parse_cookies(cookies_str);

                        let user_roles =
                            fetch_user_roles(db, authenticated_ref.sub.as_str(), Some(&role_id))
                                .await
                                .map_err(|e| {
                                    tracing::error!("Failed to fetch default roles: {}", e);
                                    ExtendedError::new(
                                        "Unauthorized",
                                        StatusCode::UNAUTHORIZED.as_str(),
                                    )
                                    .build()
                                })?;

                        let auth_claim = AuthClaim {
                            roles: user_roles.to_vec(),
                        };

                        let refresh_token_expiry_duration = Duration::from_secs(30 * 24 * 60 * 60); // days by hours by minutes by 60 seconds

                        let refresh_token_str = sign_jwt(
                            &auth_claim,
                            refresh_token_expiry_duration,
                            authenticated_ref.sub.as_str(),
                        )
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to sign access token: {}", e);
                            ExtendedError::new("Unauthorized", StatusCode::UNAUTHORIZED.as_str())
                                .build()
                        })?;

                        // Check if Host header is present
                        let g_host = match headers.get("Origin") {
                            Some(host) => {
                                // remove http:// or https:// and port(:port_number)
                                host.to_str().unwrap().split("//").collect::<Vec<&str>>()[1]
                                    .split(":")
                                    .collect::<Vec<&str>>()[0]
                            }
                            None => "127.0.0.1",
                        };

                        // Check if oauth_client cookie is present
                        match cookies.get("oauth_client") {
                            Some(oauth_client) => {
                                if oauth_client.is_empty() {
                                    tracing::debug!("auth_claim: {:?}", auth_claim);

                                    let access_token_expiry_duration =
                                        Duration::from_secs(5 * 24 * 60 * 60); // days by hours by minutes by 60 seconds

                                    let access_token_str = sign_jwt(
                                        &auth_claim,
                                        access_token_expiry_duration,
                                        authenticated_ref.sub.as_str(),
                                    )
                                    .await
                                    .map_err(|e| {
                                        tracing::error!("Failed to sign access token: {}", e);
                                        ExtendedError::new(
                                            "Unauthorized",
                                            StatusCode::UNAUTHORIZED.as_str(),
                                        )
                                        .build()
                                    })?;

                                    // Set the refresh token cookie
                                    ctx.append_http_header(
                                        SET_COOKIE,
                                        format!(
                                            "t={}; Max-Age={}; SameSite=Strict; Secure; Domain={}; HttpOnly; Path=/",
                                            refresh_token_str,
                                            refresh_token_expiry_duration.as_secs(),
                                            g_host
                                        ),
                                    );

                                    Ok(AuthDetails {
                                        token: Some(access_token_str),
                                        url: None,
                                    })
                                } else {
                                    // Set the refresh token cookie
                                    ctx.append_http_header(
                                        SET_COOKIE,
                                        format!(
                                            "oauth_user_roles_jwt={}; Max-Age={}; SameSite=Strict; Secure; Domain={}; HttpOnly; Path=/",
                                            refresh_token_str,
                                            refresh_token_expiry_duration.as_secs(),
                                            g_host
                                        ),
                                    );

                                    Ok(AuthDetails {
                                        token: None,
                                        url: None,
                                    })
                                }
                            }
                            None => Err(ExtendedError::new(
                                "Malformed request",
                                StatusCode::BAD_REQUEST.as_str(),
                            )
                            .build()),
                        }
                    }
                    None => Err(ExtendedError::new(
                        "Malformed request",
                        StatusCode::BAD_REQUEST.as_str(),
                    )
                    .build()),
                }
            }
            None => Err(
                ExtendedError::new("Malformed request", StatusCode::BAD_REQUEST.as_str()).build(),
            ),
        }
    }

    /// Create a new permission
    async fn create_permission(
        &self,
        ctx: &Context<'_>,
        mut permission_input: PermissionInput,
    ) -> Result<Permission> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:permission".into()],
            privilege: Some(AdminPrivilege::SuperAdmin),
        };

        let authenticated_ref = &authenticated;
        let authorization_constraint_ref = &authorization_constraint;

        let authorized =
            confirm_authorization(db, authenticated_ref, authorization_constraint_ref).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        permission_input.created_by = format!("user:{}", authenticated_ref.sub);
        permission_input.resource = format!("resource:{}", permission_input.resource);

        tracing::debug!("permission_input: {:?}", permission_input);

        let mut create_permission_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $permission = (CREATE permission CONTENT $permission_input RETURN AFTER);
                -- The Super Admin should be granted any permission being created automatically.
                LET $permission_id = (SELECT VALUE id FROM ONLY $permission LIMIT 1);
                LET $super_admin_roles = (SELECT VALUE id FROM role WHERE is_super_admin);
                RELATE $super_admin_roles -> granted -> $permission_id;

                RETURN $permission;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("permission_input", permission_input))
            .await
            .map_err(|e| {
                tracing::error!("Error creating permission: {}", e);
                ExtendedError::new(
                    "Failed to create permission",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        let permission_response: Option<Permission> =
            create_permission_query.take(0).map_err(|e| {
                tracing::error!("Failed to create permission: {}", e);
                ExtendedError::new(
                    "Failed to create permission",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        match permission_response {
            Some(permission) => Ok(permission),
            None => Err(ExtendedError::new(
                "Failed to create permission",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Grant a permission to a role
    async fn grant_permission(
        &self,
        ctx: &Context<'_>,
        permission_id: String,
        role_id: String,
    ) -> Result<Permission> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["grant:permission".into()],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authenticated_ref = &authenticated;
        let authorization_constraint_ref = &authorization_constraint;

        let authorized =
            confirm_authorization(db, authenticated_ref, authorization_constraint_ref).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut grant_permission_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $permission = type::thing('permission', $permission_id);
                LET $role = type::thing('role', $role_id);
                LET $user = type::thing('user', $user_id);
                LET $role_creator = (SELECT VALUE created_by FROM ONLY $role LIMIT 1);

                IF !$permission.exists() {
                    THROW 'Invalid Input: Permission does not exist!';
                };

                IF !$role.exists() {
                    THROW 'Invalid Input: Role does not exist!';
                };

                IF !$user.exists() {
                    THROW 'Invalid Input: User does not exist!';
                };

                LET $role_is_under_user_org = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(organization WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(organization WHERE created_by = $user))) > 0;
               	LET $role_is_under_user_dep = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(department WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(department WHERE created_by = $user))) > 0;

                IF $role_creator != $user AND !$role_is_under_user_org AND !$role_is_under_user_dep {
                    THROW 'Forbidden!';
                };

                LET $permission_privileges = (SELECT is_admin, is_super_admin FROM ONLY $permission);
                LET $role_privileges = (SELECT is_admin, is_super_admin FROM ONLY $role);

                IF ($permission_privileges = $role_privileges) OR ($permission_privileges.is_admin AND $role_privileges.is_super_admin) {
                    RELATE $role -> granted -> $permission;
                } ELSE {
                    THROW 'Not enough privilege!';
                };

                RETURN (SELECT * FROM ONLY $permission LIMIT 1);
                COMMIT TRANSACTION;
                ",
            )
            .bind(("permission_id", permission_id))
            .bind(("role_id", role_id))
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .await
            .map_err(|e| {
                tracing::error!("Error granting permission: {}", e);
                ExtendedError::new(
                    "Failed to grant permission",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        let permission_response: Option<Permission> =
            grant_permission_query.take(0).map_err(|e| {
                tracing::error!("Failed to grant permission: {}", e);
                ExtendedError::new(
                    "Failed to grant permission",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        match permission_response {
            Some(permission) => Ok(permission),
            None => Err(ExtendedError::new(
                "Failed to grant permission",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Revoke a permission from a role
    async fn revoke_permission(
        &self,
        ctx: &Context<'_>,
        permission_id: String,
        role_id: String,
    ) -> Result<Permission> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["revoke:permission".into()],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authenticated_ref = &authenticated;
        let authorization_constraint_ref = &authorization_constraint;

        let authorized =
            confirm_authorization(db, authenticated_ref, authorization_constraint_ref).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut revoke_permission_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $permission = type::thing('permission', $permission_id);
                LET $role = type::thing('role', $role_id);
                LET $user = type::thing('user', $user_id);
                LET $role_creator = (SELECT VALUE created_by FROM ONLY $role LIMIT 1);

                IF !$permission.exists() {
                    THROW 'Invalid Input: Permission does not exist!';
                };

                IF !$role.exists() {
                    THROW 'Invalid Input: Role does not exist!';
                };

                IF !$user.exists() {
                    THROW 'Invalid Input: User does not exist!';
                };

                LET $role_is_under_user_org = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(organization WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(organization WHERE created_by = $user))) > 0;
               	LET $role_is_under_user_dep = array::len((SELECT * FROM role WHERE id = $role AND ->is_under->(department WHERE created_by = $user))) > 0 || array::len((SELECT * FROM role WHERE id = $role AND @.{..}(->is_under->department)->is_under->(department WHERE created_by = $user))) > 0;

                IF $role_creator != $user AND !$role_is_under_user_org AND !$role_is_under_user_dep {
                    THROW 'Forbidden!';
                };

                LET $permission_privileges = (SELECT is_admin, is_super_admin FROM ONLY $permission);
                LET $role_privileges = (SELECT is_admin, is_super_admin FROM ONLY $role);

                IF ($permission_privileges = $role_privileges) OR ($permission_privileges.is_admin AND $role_privileges.is_super_admin) {
                    DELETE $role -> granted WHERE out = $permission;
                } ELSE {
                    THROW 'Not enough privilege!';
                };

                RETURN (SELECT * FROM ONLY $permission LIMIT 1);
                COMMIT TRANSACTION;
                ",
            )
            .bind(("permission_id", permission_id))
            .bind(("role_id", role_id))
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .await
            .map_err(|e| {
                tracing::error!("Error revoking permission: {}", e);
                ExtendedError::new(
                    "Failed to revoke permission",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        let permission_response: Option<Permission> =
            revoke_permission_query.take(0).map_err(|e| {
                tracing::error!("Failed to revoke permission: {}", e);
                ExtendedError::new(
                    "Failed to revoke permission",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        match permission_response {
            Some(permission) => Ok(permission),
            None => Err(ExtendedError::new(
                "Failed to revoke permission",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Create a new resource
    async fn create_resource(
        &self,
        ctx: &Context<'_>,
        mut resource_input: ResourceInput,
        resource_metadata: ResourceMetadata,
    ) -> Result<Resource> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:resource".into()],
            privilege: Some(AdminPrivilege::SuperAdmin),
        };

        let authenticated_ref = &authenticated;
        let authorization_constraint_ref = &authorization_constraint;

        let authorized =
            confirm_authorization(db, authenticated_ref, authorization_constraint_ref).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        resource_input.created_by = format!("user:{}", authenticated_ref.sub);

        let mut create_resource_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $resource = (CREATE resource CONTENT $resource_input RETURN AFTER);

                LET $resource_id = (SELECT VALUE id FROM ONLY $resource LIMIT 1);
                IF $resource_metadata.organization_id IS NOT NONE {
                    LET $organization = type::thing('organization', $resource_metadata.organization_id);

                    IF !$organization.exists() {
                        THROW 'Organization not found';
                    };
                    RELATE $resource_id -> is_under -> $organization;
                };

                IF $resource_metadata.department_id IS NOT NONE {
                    LET $department = type::thing('department', $resource_metadata.department_id);

                    IF !$department.exists() {
                        THROW 'Department not found';
                    };
                    RELATE $resource_id -> is_under -> $department;
                };

                RETURN $resource;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("resource_input", resource_input))
            .bind(("resource_metadata", resource_metadata))
            .await
            .map_err(|e| {
                tracing::error!("Error creating resource: {}", e);
                ExtendedError::new(
                    "Failed to create resource",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build()
            })?;

        let resource_response: Option<Resource> = create_resource_query.take(0).map_err(|e| {
            tracing::error!("Failed to create resource: {}", e);
            ExtendedError::new(
                "Failed to create resource",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()
        })?;

        match resource_response {
            Some(resource) => Ok(resource),
            None => Err(ExtendedError::new(
                "Failed to create resource",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }
}
