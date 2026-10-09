use std::env;

use crate::{
    integration::grpc::clients::acl_service::{
        acl_client::AclClient, ConfirmAuthenticationRequest,
    },
    utils::{
        custom_error::ApiError,
        grpc::{create_grpc_client, AuthMetaData},
        models::AuthStatus,
    },
};
use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use hyper::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use tonic::transport::Channel;
use uuid::Uuid;

pub async fn handle_auth_with_refresh(mut req: Request, next: Next) -> Result<Response, ApiError> {
    let headers = req.headers().clone();
    let headers_mut = req.headers_mut();

    let request_id = Uuid::new_v4();
    headers_mut.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).unwrap_or(HeaderValue::from_static("")),
    );

    let auth_header = headers.get(AUTHORIZATION);
    let cookie_header = headers.get(COOKIE);
    let mut request = tonic::Request::new(ConfirmAuthenticationRequest {});
    let auth_metadata: AuthMetaData<ConfirmAuthenticationRequest> = AuthMetaData {
        auth_header,
        cookie_header,
        constructed_grpc_request: Some(&mut request),
    };

    let acl_service_grpc = env::var("OAUTH_SERVICE_GRPC").map_err(|e| {
        tracing::error!("Missing the OAUTH_SERVICE_GRPC environment variable: {}", e);
        ApiError::Internal(anyhow::anyhow!("Internal Server Error"))
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
            ApiError::Unauthorized("Unauthorized".into())
        })?;

    let result = acl_grpc_client
        .confirm_authentication(request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to confirm authentication: {}", e);
            ApiError::Unauthorized("Unauthorized".into())
        })?;

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
    }

    if let Some(new_access_token) = grpc_metadata.get("new-access-token") {
        let value = new_access_token.to_str().unwrap_or("");
        response.headers_mut().insert(
            "new-access-token",
            HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
        );
    }

    Ok(response)
}

pub async fn handle_optional_auth(mut req: Request, next: Next) -> Result<Response, ApiError> {
    let request_id = Uuid::new_v4();
    req.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).unwrap_or(HeaderValue::from_static("")),
    );

    let has_auth_material =
        req.headers().contains_key(AUTHORIZATION) || req.headers().contains_key(COOKIE);

    // Anonymous request: no token, no cookie. Skip the ACL call, insert None,
    // and let the handler decide whether anonymous access is allowed.
    if !has_auth_material {
        req.extensions_mut().insert(None::<AuthStatus>);
        return Ok(next.run(req).await);
    }

    // Auth material present: try to validate it. If it fails, fall through
    // to anonymous rather than rejecting — the resource gate decides.
    let headers = req.headers().clone();
    let auth_header = headers.get(AUTHORIZATION);
    let cookie_header = headers.get(COOKIE);

    let acl_service_grpc = match env::var("OAUTH_SERVICE_GRPC") {
        Ok(v) => v,
        Err(e) => {
            // This one IS fatal — without it the service is misconfigured.
            tracing::error!("Missing the OAUTH_SERVICE_GRPC environment variable: {}", e);
            return Err(ApiError::Internal(anyhow::anyhow!("Internal Server Error")));
        }
    };

    // `request` and `auth_metadata` live entirely inside this async block.
    // `auth_metadata` mutably borrows `request`, but that borrow is released
    // when `create_grpc_client` consumes `auth_metadata` (by value), so the
    // later `confirm_authentication(request)` move is fine.
    let confirm_result: Result<_, std::io::Error> = async {
        let mut request = tonic::Request::new(ConfirmAuthenticationRequest {});

        let auth_metadata: AuthMetaData<ConfirmAuthenticationRequest> = AuthMetaData {
            auth_header,
            cookie_header,
            constructed_grpc_request: Some(&mut request),
        };

        let mut acl_grpc_client = create_grpc_client::<
            ConfirmAuthenticationRequest,
            AclClient<Channel>,
        >(&acl_service_grpc, true, Some(auth_metadata))
        .await?;

        let result = acl_grpc_client
            .confirm_authentication(request)
            .await
            .map_err(std::io::Error::other)?;

        Ok(result)
    }
    .await;

    let (auth_status, grpc_metadata) = match confirm_result {
        Ok(result) => {
            let metadata = result.metadata().clone();
            let auth_status: AuthStatus = result.into_inner().into();
            (Some(auth_status), Some(metadata))
        }
        Err(e) => {
            // Invalid/expired credentials on an optional-auth route: treat as
            // anonymous, don't reject. Log at debug, not error — this is normal.
            tracing::debug!(error = %e, "auth material present but invalid; proceeding anonymous");
            (None, None)
        }
    };

    req.extensions_mut().insert(auth_status);

    let mut response = next.run(req).await;

    // Forward any token-refresh headers the ACL service produced.
    if let Some(metadata) = grpc_metadata {
        if let Some(cookie_str) = metadata.get("set-cookie") {
            let value = cookie_str.to_str().unwrap_or("");
            response.headers_mut().insert(
                SET_COOKIE,
                HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
            );
        }

        if let Some(new_access_token) = metadata.get("new-access-token") {
            let value = new_access_token.to_str().unwrap_or("");
            response.headers_mut().insert(
                "new-access-token",
                HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
            );
        }
    }

    Ok(response)
}
