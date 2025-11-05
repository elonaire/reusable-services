use std::env;

use crate::{
    integration::grpc::clients::acl_service::{
        acl_client::AclClient, ConfirmAuthenticationRequest,
    },
    utils::{
        grpc::{create_grpc_client, AuthMetaData},
        models::AuthStatus,
    },
};
use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use hyper::header::{AUTHORIZATION, COOKIE};
use tonic::transport::Channel;

pub async fn handle_auth_with_refresh(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(AUTHORIZATION);
    let cookie_header = req.headers().get(COOKIE);

    let mut request = tonic::Request::new(ConfirmAuthenticationRequest {});

    let auth_metadata: AuthMetaData<ConfirmAuthenticationRequest> = AuthMetaData {
        auth_header,
        cookie_header,
        constructed_grpc_request: Some(&mut request),
    };
    let acl_service_grpc = env::var("OAUTH_SERVICE_GRPC").map_err(|e| {
        tracing::error!(
            "Missing the OAUTH_SERVICE_GRPC environment variable.: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let mut acl_grpc_client =
        create_grpc_client::<ConfirmAuthenticationRequest, AclClient<Channel>>(
            &acl_service_grpc,
            true,
            Some(auth_metadata),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to ACL service: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let response = acl_grpc_client.confirm_authentication(request).await;

    match response {
        Ok(response) => {
            let auth_status: AuthStatus = response.into_inner().into();
            // Insert auth_status into the req extensions
            req.extensions_mut().insert(auth_status);
            Ok(next.run(req).await)
        }
        Err(_e) => return Err(StatusCode::UNAUTHORIZED),
    }
}
