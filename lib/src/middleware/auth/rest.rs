use crate::{
    integration::grpc::clients::acl_service::{acl_client::AclClient, Empty},
    utils::grpc::{create_grpc_client, AuthMetaData},
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

    let mut request = tonic::Request::new(Empty {});

    let auth_metadata: AuthMetaData<Empty> = AuthMetaData {
        auth_header,
        cookie_header,
        constructed_grpc_request: Some(&mut request),
    };
    let mut acl_grpc_client = create_grpc_client::<Empty, AclClient<Channel>>(
        "http://[::1]:50051",
        true,
        Some(auth_metadata),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to connect to ACL service: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let response = acl_grpc_client.check_auth(request).await;

    match response {
        Ok(response) => {
            let current_user = response.into_inner().sub;
            // Insert current user to the req extensions(response.sub)
            req.extensions_mut().insert(current_user);
            Ok(next.run(req).await)
        }
        Err(_e) => return Err(StatusCode::UNAUTHORIZED),
    }
}
