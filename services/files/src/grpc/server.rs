use std::sync::Arc;

use files_service::{
    files_service_server::FilesService, FileId, FileName, PurchaseFileDetails, PurchaseFileResponse,
};
use surrealdb::{engine::remote::ws::Client, Surreal};
use tonic::{Request, Response, Status};

use crate::utils;

pub mod files_service {
    tonic::include_proto!("files");
}

// #[derive(Debug, Default)]
pub struct FilesServiceImplementation {
    db: Arc<Surreal<Client>>,
}

impl FilesServiceImplementation {
    pub fn new(db: Arc<Surreal<Client>>) -> Self {
        Self { db }
    }
}

impl From<files_service::PurchaseFileDetails> for lib::utils::models::PurchaseFileDetails {
    fn from(file_details: files_service::PurchaseFileDetails) -> Self {
        Self {
            file_id: file_details.file_id, // Ensuring `Option<String>`
            buyer_id: file_details.buyer_id,
        }
    }
}

#[tonic::async_trait]
impl FilesService for FilesServiceImplementation {
    async fn get_file_id(&self, request: Request<FileName>) -> Result<Response<FileId>, Status> {
        match utils::files::get_file_id(&self.db, request.into_inner().file_name).await {
            Ok(file_id) => Ok(Response::new(FileId { file_id })),
            Err(_e) => Err(Status::not_found("Invalid file name")),
        }
    }

    async fn get_file_name(&self, request: Request<FileId>) -> Result<Response<FileName>, Status> {
        match utils::files::get_system_filename(&self.db, request.into_inner().file_id).await {
            Ok(file_name) => Ok(Response::new(FileName { file_name })),
            Err(_e) => Err(Status::not_found("Invalid file ID")),
        }
    }

    async fn purchase_file(
        &self,
        request: Request<PurchaseFileDetails>,
    ) -> Result<Response<PurchaseFileResponse>, Status> {
        match utils::files::purchase_file(&self.db, request.into_inner().into()).await {
            Ok(response) => Ok(Response::new(PurchaseFileResponse { success: response })),
            Err(_e) => Err(Status::internal("Failed")),
        }
    }
}
