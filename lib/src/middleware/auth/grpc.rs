use std::env;
use std::time::Instant;

use axum::http::HeaderValue;
use hyper::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use tonic::body::BoxBody;
use tonic::codegen::http::{Request, Response};
use tonic::transport::Channel;
use tonic::Status;
use tonic_middleware::{Middleware, ServiceBound};

use crate::integration::grpc::clients::acl_service::{
    acl_client::AclClient, ConfirmAuthenticationRequest,
};
use crate::utils::grpc::{create_grpc_client, AuthMetaData};

#[derive(Default, Clone)]
pub struct AuthMiddleware;

#[async_trait::async_trait]
impl<S> Middleware<S> for AuthMiddleware
where
    S: ServiceBound,
    S::Future: Send,
    S::Error: From<tonic::Status> + Send + 'static, // Add Error constraint
{
    async fn call(
        &self,
        mut req: Request<BoxBody>,
        mut service: S,
    ) -> Result<Response<BoxBody>, S::Error> {
        let start_time = Instant::now();
        // Call the service. You can also intercept request from middleware.
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
            Status::internal("Server Error")
        })?;

        let mut acl_grpc_client = create_grpc_client::<
            ConfirmAuthenticationRequest,
            AclClient<Channel>,
        >(&acl_service_grpc, true, Some(auth_metadata))
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to ACL service: {}", e);
            Status::unavailable("Failed to connect to ACL service")
        })?;

        let result = acl_grpc_client.confirm_authentication(request).await?;
        let result_metadata = result.metadata().clone();

        let auth_status = result.into_inner();
        // Insert auth_status into the req extensions
        req.extensions_mut().insert(auth_status);
        let mut response = service.call(req).await?;
        let mut response_headers = response.headers_mut().clone();

        if let Some(cookie_str) = result_metadata.get("set-cookie") {
            let value = cookie_str.to_str().unwrap_or("");
            response_headers.insert(
                SET_COOKIE,
                HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
            );
        };
        if let Some(new_access_token) = result_metadata.get("new-access-token") {
            let value = new_access_token.to_str().unwrap_or("");
            response_headers.insert(
                "new-access-token",
                HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
            );
        };

        let elapsed_time = start_time.elapsed();
        tracing::info!("gRPC request processed in {:?}", elapsed_time);

        Ok(response)
    }
}
