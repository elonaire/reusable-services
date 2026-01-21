use std::sync::Arc;

use lib::integration::grpc::clients::{
    acl_service::{AuthStatus, ConfirmAuthenticationResponse},
    files_service::{
        files_service_server::FilesService, CreateFileFromContentRequest,
        CreateFileFromContentResponse, FetchFileIdRequest, FetchFileIdResponse,
        FetchFileNameRequest, FetchFileNameResponse, PurchaseFileRequest, PurchaseFileResponse,
    },
};
use surrealdb::{engine::remote::ws::Client, Surreal};
use tonic::{Request, Response, Status};

use crate::utils;

// #[derive(Debug, Default)]
pub struct FilesServiceImplementation {
    db: Arc<Surreal<Client>>,
}

impl FilesServiceImplementation {
    pub fn new(db: Arc<Surreal<Client>>) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl FilesService for FilesServiceImplementation {
    async fn fetch_file_id(
        &self,
        request: Request<FetchFileIdRequest>,
    ) -> Result<Response<FetchFileIdResponse>, Status> {
        match utils::files::get_file_id(&self.db, request.into_inner().file_name).await {
            Ok(file_id) => Ok(Response::new(FetchFileIdResponse { file_id })),
            Err(_e) => Err(Status::not_found("Invalid file name")),
        }
    }

    async fn fetch_file_name(
        &self,
        request: Request<FetchFileNameRequest>,
    ) -> Result<Response<FetchFileNameResponse>, Status> {
        match utils::files::get_system_filename(&self.db, request.into_inner().file_id).await {
            Ok(file_name) => Ok(Response::new(FetchFileNameResponse { file_name })),
            Err(_e) => Err(Status::not_found("Invalid file ID")),
        }
    }

    async fn purchase_file(
        &self,
        request: Request<PurchaseFileRequest>,
    ) -> Result<Response<PurchaseFileResponse>, Status> {
        match utils::files::purchase_file(&self.db, request.into_inner().into()).await {
            Ok(response) => Ok(Response::new(PurchaseFileResponse { success: response })),
            Err(_e) => Err(Status::internal("Failed")),
        }
    }

    async fn create_file_from_content(
        &self,
        request: Request<CreateFileFromContentRequest>,
    ) -> Result<Response<CreateFileFromContentResponse>, Status> {
        let auth_status = request
            .extensions()
            .get::<ConfirmAuthenticationResponse>()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("Unauthorized"))?;

        let payload = request.into_inner();
        match utils::files::create_file_from_content(&self.db, &payload.into(), &auth_status.sub)
            .await
        {
            Ok(file_id) => Ok(Response::new(CreateFileFromContentResponse { file_id })),
            Err(_e) => Err(Status::internal("Failed")),
        }
    }
}
