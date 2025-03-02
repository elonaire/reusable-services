use email_service::{email_server::Email, EmailPayload, EmailResponse};
use tonic::{Request, Response, Status};

pub mod email_service {
    tonic::include_proto!("email");
}

#[derive(Debug, Default)]
pub struct EmailServiceImplementation;

#[tonic::async_trait]
impl Email for EmailServiceImplementation {
    async fn send_email(
        &self,
        request: Request<EmailPayload>,
    ) -> Result<Response<EmailResponse>, Status> {
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
        Ok(Response::new(EmailResponse {
            message: "Email sent successfully".to_string(),
        }))
    }
}
