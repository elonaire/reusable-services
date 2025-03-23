use std::time::Instant;

use hyper::header::{AUTHORIZATION, COOKIE};
use tonic::body::BoxBody;
use tonic::codegen::http::{Request, Response};
use tonic::metadata::MetadataValue;
use tonic::Status;
// Use this instead of tonic::Request/tonic::Response in Middleware!
use hyper::header::HeaderValue;
use tonic_middleware::{Middleware, ServiceBound};

use crate::integration::grpc::clients::acl_service::{acl_client::AclClient, Empty};

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
        tracing::debug!("Starting middleware");
        // Call the service. You can also intercept request from middleware.
        let mut acl_grpc_client = AclClient::connect("http://[::1]:50051")
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to ACL service: {}", e);
                Status::unavailable("Failed to connect to ACL service")
            })?;

        let mut request = tonic::Request::new(Empty {});

        let default_header_value = HeaderValue::from_static("");

        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .unwrap_or(&default_header_value);
        let cookie_header = req.headers().get(COOKIE).unwrap_or(&default_header_value);

        let token: MetadataValue<_> = auth_header
            .to_str()
            .unwrap()
            .parse()
            .map_err(|_e| Status::unauthenticated("Failed to authenticate"))?;

        request.metadata_mut().insert("authorization", token);

        let cookie: MetadataValue<_> = cookie_header
            .to_str()
            .unwrap()
            .parse()
            .map_err(|_e| Status::unauthenticated("Failed to authenticate"))?;

        request.metadata_mut().insert("cookie", cookie);

        let response = acl_grpc_client.check_auth(request).await?;
        tracing::debug!("Received response from ACL service");

        let current_user = response.into_inner().sub;
        // Insert current user to the req extensions(response.sub)
        req.extensions_mut().insert(current_user);
        let result = service.call(req).await?;

        let elapsed_time = start_time.elapsed();
        tracing::info!("Request processed in {:?}", elapsed_time);

        Ok(result)
    }
}
