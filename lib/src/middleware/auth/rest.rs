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
use axum::{
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use hyper::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use tonic::transport::Channel;

pub async fn handle_auth_with_refresh(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers().clone();

    let auth_header = headers.get(AUTHORIZATION);
    let cookie_header = headers.get(COOKIE);

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

    let result = acl_grpc_client.confirm_authentication(request).await;

    match result {
        Ok(result) => {
            let grpc_metadata = result.metadata().clone();

            let auth_status: AuthStatus = result.into_inner().into();

            req.extensions_mut().insert(auth_status);
            let mut response = next.run(req).await;

            if let Some(cookie_str) = grpc_metadata.get("set-cookie") {
                let value = cookie_str.to_str().unwrap_or("");
                response.headers_mut().insert(
                    SET_COOKIE,
                    HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
                );
            };
            if let Some(new_access_token) = grpc_metadata.get("new-access-token") {
                let value = new_access_token.to_str().unwrap_or("");
                response.headers_mut().insert(
                    "new-access-token",
                    HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
                );
            };

            Ok(response)
        }
        Err(_e) => return Err(StatusCode::UNAUTHORIZED),
    }
}
