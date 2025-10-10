use lib::integration::grpc::clients::email_service::{
    email_service_server::EmailService, SendEmailRequest, SendEmailResponse,
};
use tonic::{Request, Response, Status};

use crate::utils;

#[derive(Debug, Default)]
pub struct EmailServiceImplementation;

#[tonic::async_trait]
impl EmailService for EmailServiceImplementation {
    async fn send_email(
        &self,
        request: Request<SendEmailRequest>,
    ) -> Result<Response<SendEmailResponse>, Status> {
        let send_email_res = utils::email::send_email(&request.into_inner().into()).await;

        match send_email_res {
            Ok(send_email_res) => Ok(Response::new(SendEmailResponse {
                message: send_email_res.to_owned(),
            })),
            Err(e) => Err(e.into()),
        }
    }
}
