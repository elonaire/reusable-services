use std::{env, sync::Arc};

use axum::http::HeaderValue;
use hyper::header::{AUTHORIZATION, COOKIE};
use hyper::HeaderMap;
use jwt_simple::prelude::*;
use lib::integration::grpc::clients::acl_service::{
    ConfirmAuthenticationRequest, ConfirmAuthenticationResponse, ConfirmAuthorizationRequest,
    ConfirmAuthorizationResponse, SignInAsServiceRequest, SignInAsServiceResponse,
};
use lib::utils::auth::AuthClaim;
use lib::utils::models::{AuthStatus, AuthorizationConstraint};
use surrealdb::engine::remote::ws::Client;
use surrealdb::Surreal;
use tonic::{Request, Response, Status};

use crate::graphql::schemas::user::UserLogins;
use crate::utils::auth::{
    confirm_authentication, confirm_authorization, get_user_email, sign_jwt,
    verify_login_credentials,
};

use lib::integration::grpc::clients::acl_service::{
    acl_server::Acl, GetUserEmailRequest, GetUserEmailResponse,
};

// #[derive(Default)]
pub struct AclServiceImplementation {
    db: Arc<Surreal<Client>>,
}

impl AclServiceImplementation {
    pub fn new(db: Arc<Surreal<Client>>) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl Acl for AclServiceImplementation {
    async fn confirm_authentication(
        &self,
        request: Request<ConfirmAuthenticationRequest>,
    ) -> Result<Response<ConfirmAuthenticationResponse>, Status> {
        let metadata = request.metadata();
        let token = metadata
            .get("authorization")
            .ok_or(Status::unauthenticated("Unauthorized"))?;
        let cookie = metadata
            .get("cookie")
            .ok_or(Status::unauthenticated("Unauthorized"))?;

        let token_header_value = HeaderValue::from_str(token.to_str().unwrap_or(""))
            .map_err(|_e| Status::unauthenticated("Unauthorized"))?;
        let cookie_header_value = HeaderValue::from_str(cookie.to_str().unwrap_or(""))
            .map_err(|_e| Status::unauthenticated("Unauthorized"))?;

        let mut header_map = HeaderMap::new();
        header_map.insert(AUTHORIZATION, token_header_value);
        header_map.insert(COOKIE, cookie_header_value);

        match confirm_authentication(Some(&header_map), &self.db).await {
            Ok(auth_status) => Ok(Response::new(auth_status.into())),
            Err(e) => {
                tracing::error!("Authentication failed: {}", e);
                Err(Status::unauthenticated("Unauthorized"))
            }
        }
    }

    async fn sign_in_as_service(
        &self,
        _request: Request<SignInAsServiceRequest>,
    ) -> Result<Response<SignInAsServiceResponse>, Status> {
        let username = env::var("INTERNAL_USER").map_err(|e| {
            tracing::error!("Missing the INTERNAL_USER environment variable.: {}", e);
            Status::internal("Server Error")
        })?;
        let password = env::var("INTERNAL_USER_PASSWORD").map_err(|e| {
            tracing::error!(
                "Missing the INTERNAL_USER_PASSWORD environment variable.: {}",
                e
            );
            Status::internal("Server Error")
        })?;

        let raw_user_details = UserLogins {
            user_name: Some(username),
            password: Some(password),
            oauth_client: None,
        };

        match verify_login_credentials(&self.db, &raw_user_details).await {
            Ok(user) => {
                let auth_claim = AuthClaim { roles: vec![] };
                let service_token_expiry_duration = Duration::from_secs(30);

                let signed_jwt = sign_jwt(
                    &auth_claim,
                    service_token_expiry_duration,
                    &user
                        .id
                        .as_ref()
                        .map(|t| &t.id)
                        .ok_or("Unauthorized")
                        .map_err(|e| {
                            tracing::error!("Failed to get user ID: {}", e);
                            Status::unauthenticated("Unauthorized")
                        })?
                        .to_raw(),
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to sign JWT: {}", e);
                    Status::unauthenticated("Unauthorized")
                })?;

                Ok(Response::new(SignInAsServiceResponse { token: signed_jwt }))
            }
            Err(e) => {
                tracing::error!("Authentication failed: {}", e);
                Err(Status::unauthenticated("Unauthorized"))
            }
        }
    }

    async fn get_user_email(
        &self,
        request: Request<GetUserEmailRequest>,
    ) -> Result<Response<GetUserEmailResponse>, Status> {
        let user_id = request.into_inner().user_id;

        match get_user_email(&self.db, user_id.as_str()).await {
            Ok(email) => Ok(Response::new(GetUserEmailResponse { email })),
            Err(e) => {
                tracing::error!("Failed to get user email: {}", e);
                Err(Status::not_found("User not found"))
            }
        }
    }

    async fn confirm_authorization(
        &self,
        request: Request<ConfirmAuthorizationRequest>,
    ) -> Result<Response<ConfirmAuthorizationResponse>, Status> {
        let request_body = request.into_inner();
        let auth_status = request_body.auth_status;
        let authorization_constraint = request_body.authorization_constraint;

        if auth_status.is_none() {
            return Err(Status::unauthenticated("Unauthenticated!"));
        }

        if authorization_constraint.is_none() {
            return Err(Status::invalid_argument(
                "Authorization constraint not supported!",
            ));
        }

        let auth_status: AuthStatus = auth_status.unwrap().into();
        let authorization_constraint: AuthorizationConstraint =
            authorization_constraint.unwrap().into();

        match confirm_authorization(&self.db, &auth_status, authorization_constraint).await {
            Ok(res) => Ok(Response::new(ConfirmAuthorizationResponse { is_auth: res })),
            Err(e) => {
                tracing::error!("Failed to confirm authorization: {}", e);
                Err(Status::permission_denied("Failed to confirm authorization"))
            }
        }
    }
}
