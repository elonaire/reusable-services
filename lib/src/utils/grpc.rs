use async_trait::async_trait;
use hyper::{
    header::{HeaderValue, AUTHORIZATION, COOKIE},
    HeaderMap,
};
use std::{
    env,
    io::{Error as StdError, ErrorKind},
};
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, Endpoint, Error},
    Request,
};

use crate::{
    integration::grpc::clients::{
        acl_service::{acl_client::AclClient, ConfirmAuthorizationRequest},
        email_service::email_service_client::EmailServiceClient,
        files_service::files_service_client::FilesServiceClient,
        payments_service::payments_service_client::PaymentsServiceClient,
    },
    utils::models::{AuthStatus, AuthorizationConstraint},
};

// Define the trait for gRPC clients
#[async_trait]
pub trait GrpcClient: Sized {
    async fn connect<'a>(endpoint: &'a str) -> Result<Self, Error>;
}

pub struct AuthMetaData<'a, T> {
    pub auth_header: Option<&'a HeaderValue>,
    pub cookie_header: Option<&'a HeaderValue>,
    pub constructed_grpc_request: Option<&'a mut Request<T>>,
}

impl<'a, T> std::fmt::Debug for AuthMetaData<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safely format header values as strings
        let auth_header = self
            .auth_header
            .map(|h| h.to_str().unwrap_or("<invalid UTF-8>"))
            .unwrap_or("<none>");
        let cookie_header = self
            .cookie_header
            .map(|h| h.to_str().unwrap_or("<invalid UTF-8>"))
            .unwrap_or("<none>");

        f.debug_struct("AuthMetaData")
            .field("auth_header", &auth_header)
            .field("cookie_header", &cookie_header)
            // You can’t safely print a &mut Request<T> without borrowing it
            // So just indicate its presence
            .field(
                "constructed_grpc_request",
                &self
                    .constructed_grpc_request
                    .as_ref()
                    .map(|_| "<some request>")
                    .unwrap_or("<none>"),
            )
            .finish()
    }
}

// Implement the trait for AclClient<Channel>
#[async_trait]
impl GrpcClient for AclClient<Channel> {
    async fn connect<'a>(endpoint: &'a str) -> Result<Self, Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;
        Ok(AclClient::new(channel))
    }
}

// Implement the trait for EmailServiceClient<Channel>
#[async_trait]
impl GrpcClient for EmailServiceClient<Channel> {
    async fn connect<'a>(endpoint: &'a str) -> Result<Self, Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;
        Ok(EmailServiceClient::new(channel))
    }
}

// Implement the trait for FilesServiceClient<Channel>
#[async_trait]
impl GrpcClient for FilesServiceClient<Channel> {
    async fn connect<'a>(endpoint: &'a str) -> Result<Self, Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;
        Ok(FilesServiceClient::new(channel))
    }
}

// Implement the trait for PaymentsServiceClient<Channel>
#[async_trait]
impl GrpcClient for PaymentsServiceClient<Channel> {
    async fn connect<'a>(endpoint: &'a str) -> Result<Self, Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;
        Ok(PaymentsServiceClient::new(channel))
    }
}

// Generic function to create gRPC clients
pub async fn create_grpc_client<'a, R, T: GrpcClient>(
    endpoint: &str,
    is_authenticated: bool,
    auth_metadata: Option<AuthMetaData<'_, R>>,
) -> Result<T, StdError> {
    if is_authenticated && auth_metadata.is_some() {
        add_auth_headers_to_request::<R>(auth_metadata.unwrap()).await?;
    }
    T::connect(endpoint)
        .await
        .map_err(|_e| StdError::new(ErrorKind::InvalidData, "Invalid header"))
}

async fn add_auth_headers_to_request<R>(
    mut auth_metadata: AuthMetaData<'_, R>,
) -> Result<(), StdError> {
    if auth_metadata.auth_header.is_none()
        || auth_metadata.cookie_header.is_none()
        || auth_metadata.constructed_grpc_request.is_none()
    {
        return Err(StdError::new(ErrorKind::InvalidData, "Invalid request"));
    }

    let token: MetadataValue<_> = auth_metadata
        .auth_header
        .unwrap()
        .to_str()
        .map_err(|e| {
            tracing::error!("Failed to convert auth header to str: {}", e);
            StdError::new(ErrorKind::InvalidData, "Invalid header")
        })?
        .parse()
        .map_err(|e| {
            tracing::error!("Failed to parse auth header: {}", e);
            StdError::new(ErrorKind::InvalidData, "Invalid header")
        })?;

    auth_metadata
        .constructed_grpc_request
        .as_mut()
        .unwrap()
        .metadata_mut()
        .insert("authorization", token);

    let cookie: MetadataValue<_> = auth_metadata
        .cookie_header
        .unwrap()
        .to_str()
        .map_err(|e| {
            tracing::error!("Failed to convert auth header to str: {}", e);
            StdError::new(ErrorKind::InvalidData, "Invalid header")
        })?
        .parse()
        .map_err(|e| {
            tracing::error!("Failed to parse cookie header: {}", e);
            StdError::new(ErrorKind::InvalidData, "Invalid header")
        })?;

    auth_metadata
        .constructed_grpc_request
        .as_mut()
        .unwrap()
        .metadata_mut()
        .insert("cookie", cookie);

    Ok(())
}

pub async fn confirm_authorization(
    auth_status: &AuthStatus,
    authorization_constraint: &AuthorizationConstraint,
    headers: &HeaderMap,
) -> Result<bool, StdError> {
    let auth_header = headers.get(AUTHORIZATION);
    let cookie_header = headers.get(COOKIE);

    let mut request = tonic::Request::new(ConfirmAuthorizationRequest {
        auth_status: Some(auth_status.to_owned().into()),
        authorization_constraint: Some(authorization_constraint.to_owned().into()),
    });

    let auth_metadata: AuthMetaData<ConfirmAuthorizationRequest> = AuthMetaData {
        auth_header: auth_header,
        cookie_header: cookie_header,
        constructed_grpc_request: Some(&mut request),
    };

    let acl_service_grpc = env::var("OAUTH_SERVICE_GRPC").map_err(|e| {
        tracing::error!(
            "Missing the OAUTH_SERVICE_GRPC environment variable.: {}",
            e
        );
        StdError::new(ErrorKind::Other, "Server Error")
    })?;

    let mut acl_grpc_client =
        create_grpc_client::<ConfirmAuthorizationRequest, AclClient<Channel>>(
            &acl_service_grpc,
            true,
            Some(auth_metadata),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to ACL service: {}", e);
            StdError::new(ErrorKind::Other, "Failed to connect to ACL service")
        })?;

    let response = acl_grpc_client.confirm_authorization(request).await;

    match response {
        Ok(response) => {
            let is_authorized = response.into_inner().is_auth;
            Ok(is_authorized)
        }
        Err(_e) => Err(StdError::new(ErrorKind::PermissionDenied, "Unauthorized")),
    }
}
