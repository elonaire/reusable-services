use crate::{
    integration::grpc::clients::acl_service::{
        acl_client::AclClient, ConfirmAuthenticationRequest,
    },
    utils::{
        grpc::{create_grpc_client, AuthMetaData},
        models::AuthStatus,
    },
};

use async_graphql::Context;
use hyper::{
    header::{AUTHORIZATION, COOKIE, SET_COOKIE},
    HeaderMap,
};
use std::{
    env,
    io::{Error, ErrorKind},
};
use tonic::transport::Channel;

/// False middleware for checking authentication from ACL service for GraphQL requests.
/// I used this anti-pattern because the middleware in async-graphql just doesn't work. The headers are not properly parsed.
pub async fn confirm_authentication(ctx: &Context<'_>) -> Result<AuthStatus, Error> {
    let headers = ctx.data::<HeaderMap>().map_err(|e| {
        tracing::error!("Error HeaderMap: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
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
        Error::new(ErrorKind::Other, "Server Error")
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
            Error::new(ErrorKind::Other, "Failed to connect to ACL service")
        })?;

    let response = acl_grpc_client.confirm_authentication(request).await;

    match response {
        Ok(response) => {
            let response_headers = response.metadata().clone();

            if let Some(cookie_str) = response_headers.get("set-cookie") {
                ctx.insert_http_header(SET_COOKIE, cookie_str.to_str().unwrap_or(""));
            };
            if let Some(new_access_token) = response_headers.get("new-access-token") {
                ctx.append_http_header("new-access-token", new_access_token.to_str().unwrap_or(""));
            };
            let auth_status = response.into_inner().into();
            Ok(auth_status)
        }
        Err(_e) => return Err(Error::new(ErrorKind::PermissionDenied, "Unauthorized")),
    }
}
