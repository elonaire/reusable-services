use crate::integration::grpc::clients::acl_service::{acl_client::AclClient, Empty};
use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use hyper::header::{AUTHORIZATION, COOKIE};
use tonic::metadata::MetadataValue;

pub async fn handle_auth_with_refresh(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut acl_grpc_client = AclClient::connect("http://[::1]:50051")
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to ACL service: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut request = tonic::Request::new(Empty {});

    let auth_header = req.headers().get(AUTHORIZATION);
    let cookie_header = req.headers().get(COOKIE);

    if auth_header.is_some() {
        let token: MetadataValue<_> = auth_header
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .map_err(|_e| StatusCode::UNAUTHORIZED)?;

        request.metadata_mut().insert("authorization", token);
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if cookie_header.is_some() {
        let cookie: MetadataValue<_> = cookie_header
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .map_err(|_e| StatusCode::UNAUTHORIZED)?;

        request.metadata_mut().insert("cookie", cookie);
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

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
