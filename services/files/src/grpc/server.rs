use std::sync::Arc;

use files_service::{files_service_server::FilesService, FileId, FileName};
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

#[tonic::async_trait]
impl FilesService for FilesServiceImplementation {
    async fn get_file_id(&self, request: Request<FileName>) -> Result<Response<FileId>, Status> {
        // if token != "Bearer my-secret-token" {
        // return Err(Status::unauthenticated("Invalid token"));
        // Sample client request
        // async fn send_authenticated_request(mut client: EmailClient<Channel>) -> Result<(), Box<dyn std::error::Error>> {
        //     let mut request = Request::new(SomeRequest {});
        //     let token: MetadataValue<_> = "Bearer my-secret-token".parse()?;

        //     request.metadata_mut().insert("authorization", token);
        //     let _response = client.some_method(request).await?;

        //     Ok(())
        // }
        // }
        match utils::files::get_file_id(&self.db, request.into_inner().file_name).await {
            Ok(file_id) => Ok(Response::new(FileId { file_id })),
            Err(_e) => Err(Status::internal("Failed")),
        }
    }

    async fn get_file_name(&self, request: Request<FileId>) -> Result<Response<FileName>, Status> {
        match utils::files::get_system_filename(&self.db, request.into_inner().file_id).await {
            Ok(file_name) => Ok(Response::new(FileName { file_name })),
            Err(_e) => Err(Status::internal("Failed")),
        }
    }
}
