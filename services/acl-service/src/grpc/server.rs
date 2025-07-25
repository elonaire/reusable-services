use std::{env, sync::Arc};

use axum::http::HeaderValue;
use hyper::header::{AUTHORIZATION, COOKIE};
use hyper::HeaderMap;
use jwt_simple::prelude::*;
use lib::utils::auth::AuthClaim;
use surrealdb::engine::remote::ws::Client;
use surrealdb::Surreal;
use tonic::{Request, Response, Status};

use crate::graphql::schemas::user::UserLogins;
use crate::utils::auth::{
    confirm_authentication, get_user_email, sign_jwt, verify_login_credentials,
};

use lib::integration::grpc::clients::acl_service::{
    acl_server::Acl, AuthDetails, AuthStatus, Empty, GetUserEmailRequest, GetUserEmailResponse,
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
        request: Request<Empty>,
    ) -> Result<Response<AuthStatus>, Status> {
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
            Err(_e) => Err(Status::unauthenticated("Unauthorized")),
        }
    }

    async fn sign_in_as_service(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AuthDetails>, Status> {
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
                            tracing::error!("{}", e);
                            Status::unauthenticated("Unauthorized")
                        })?
                        .to_raw(),
                )
                .await
                .map_err(|_e| Status::unauthenticated("Unauthorized"))?;

                Ok(Response::new(AuthDetails { token: signed_jwt }))
            }
            Err(_e) => Err(Status::unauthenticated("Unauthorized")),
        }
    }

    async fn get_user_email(
        &self,
        request: Request<GetUserEmailRequest>,
    ) -> Result<Response<GetUserEmailResponse>, Status> {
        let user_id = request.into_inner().user_id;

        match get_user_email(&self.db, user_id.as_str()).await {
            Ok(email) => Ok(Response::new(GetUserEmailResponse { email })),
            Err(_e) => Err(Status::not_found("User not found")),
        }
    }
}
