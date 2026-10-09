use std::env;
use std::time::Instant;

use axum::http::HeaderValue;
use tonic::body::Body;
use tonic::codegen::http::{Request, Response};
use tonic::transport::Channel;
use tonic::Status;
use tonic_middleware::{Middleware, RequestInterceptor, ServiceBound};

use crate::integration::grpc::clients::acl_service::{
    acl_client::AclClient, ConfirmAuthenticationRequest,
};
use crate::utils::grpc::{create_grpc_client, AuthMetaData};

#[derive(Default, Clone)]
pub struct AuthMiddleware;

#[derive(Clone)]
struct AuthResponseHeaders {
    set_cookie: Option<HeaderValue>,
    new_access_token: Option<HeaderValue>,
}

#[async_trait::async_trait]
impl RequestInterceptor for AuthMiddleware {
    async fn intercept(&self, mut req: Request<Body>) -> Result<Request<Body>, Status> {
        let auth_header = req.headers().get("authorization");
        let cookie_header = req.headers().get("cookie");

        let mut request = tonic::Request::new(ConfirmAuthenticationRequest {});

        let auth_metadata: AuthMetaData<ConfirmAuthenticationRequest> = AuthMetaData {
            auth_header,
            cookie_header,
            constructed_grpc_request: Some(&mut request),
        };

        let acl_service_grpc = env::var("OAUTH_SERVICE_GRPC").map_err(|e| {
            tracing::error!("Missing the OAUTH_SERVICE_GRPC environment variable: {}", e);

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

        /*
         * Capture the ACL response metadata before consuming the response.
         */
        let response_headers = AuthResponseHeaders {
            set_cookie: result
                .metadata()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| HeaderValue::from_str(value).ok()),

            new_access_token: result
                .metadata()
                .get("new-access-token")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| HeaderValue::from_str(value).ok()),
        };

        /*
         * Authentication information returned by ACL.
         */
        let auth_status = result.into_inner();

        /*
         * Make the authenticated user/session information available
         * to the actual gRPC service.
         */
        req.extensions_mut().insert(auth_status);

        /*
         * The response headers cannot be added yet because an interceptor
         * only has access to the incoming request.
         *
         * Store them in request extensions so AuthResponseMiddleware can
         * copy them onto the outgoing response.
         */
        req.extensions_mut().insert(response_headers);

        Ok(req)
    }
}

#[derive(Default, Clone)]
pub struct AuthResponseMiddleware;

#[async_trait::async_trait]
impl<S> Middleware<S> for AuthResponseMiddleware
where
    S: ServiceBound,
    S::Future: Send,
{
    async fn call(&self, req: Request<Body>, mut service: S) -> Result<Response<Body>, S::Error> {
        let start_time = Instant::now();

        /*
         * Grab the authentication response headers before the request
         * is passed to the actual service.
         */
        let response_headers = req.extensions().get::<AuthResponseHeaders>().cloned();

        /*
         * Call the actual gRPC service.
         */
        let mut response = service.call(req).await?;

        /*
         * Propagate ACL response metadata to the final gRPC response.
         */
        if let Some(headers) = response_headers {
            if let Some(set_cookie) = headers.set_cookie {
                response.headers_mut().insert("set-cookie", set_cookie);
            }

            if let Some(new_access_token) = headers.new_access_token {
                response
                    .headers_mut()
                    .insert("new-access-token", new_access_token);
            }
        }

        let elapsed_time = start_time.elapsed();

        tracing::info!("gRPC request processed in {:?}", elapsed_time);

        Ok(response)
    }
}
