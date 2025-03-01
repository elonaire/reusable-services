use std::{env, sync::Arc};

use acl_service::acl_server::Acl;
use acl_service::{AuthDetails, AuthStatus, Empty};
use axum::http::HeaderValue;
use jwt_simple::prelude::*;
use lib::utils::auth::AuthClaim;
use surrealdb::engine::remote::ws::Client;
use surrealdb::Surreal;
use tonic::{Request, Response, Status};

use crate::graphql::schemas::user::UserLogins;
use crate::utils::auth::{decode_token, sign_jwt, verify_login_credentials};

pub mod acl_service {
    tonic::include_proto!("acl");
}

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
    async fn check_auth(&self, request: Request<Empty>) -> Result<Response<AuthStatus>, Status> {
        let metadata = request.metadata();
        let token = metadata
            .get("authorization")
            .ok_or(Status::unauthenticated("Unauthorized"))?;
        let header_value = match HeaderValue::from_str(token.to_str().unwrap_or("")) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Failed to fetch key: {}", e);
                return Err(Status::unauthenticated("Unauthorized"));
            }
        };

        match decode_token(&self.db, &header_value).await {
            Ok(claims) => Ok(Response::new(AuthStatus {
                is_auth: true,
                sub: claims
                    .subject
                    .as_ref()
                    .map(|t| t.to_string())
                    .unwrap_or("".to_string()),
            })),
            Err(_e) => Err(Status::unauthenticated("Unauthorized")),
        }

        // if token != "Bearer my-secret-token" {
        // return Err(Status::unauthenticated("Invalid token"));
        // Sample client request
        // async fn send_authenticated_request(mut client: AclClient<Channel>) -> Result<(), Box<dyn std::error::Error>> {
        //     let mut request = Request::new(SomeRequest {});
        //     let token: MetadataValue<_> = "Bearer my-secret-token".parse()?;

        //     request.metadata_mut().insert("authorization", token);
        //     let _response = client.some_method(request).await?;

        //     Ok(())
        // }
        // }
    }

    async fn sign_in_as_service(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AuthDetails>, Status> {
        let username =
            env::var("INTERNAL_USER").expect("Missing the INTERNAL_USER environment variable.");
        let password = env::var("INTERNAL_USER_PASSWORD")
            .expect("Missing the INTERNAL_USER_PASSWORD environment variable.");

        let raw_user_details = UserLogins {
            user_name: Some(username),
            password: Some(password),
            oauth_client: None,
        };

        match verify_login_credentials(&self.db, &raw_user_details).await {
            Ok(user) => {
                let auth_claim = AuthClaim { roles: vec![] };
                let service_token_expiry_duration = Duration::from_secs(30);

                let signed_jwt =
                    sign_jwt(&self.db, &auth_claim, service_token_expiry_duration, &user)
                        .await
                        .map_err(|_e| Status::unauthenticated("Unauthorized"))?;

                Ok(Response::new(AuthDetails { token: signed_jwt }))
            }
            Err(_e) => Err(Status::unauthenticated("Unauthorized")),
        }
    }
}
