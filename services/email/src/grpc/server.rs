use email_service::{email_service_server::EmailService, EmailResponse};
use tonic::{Request, Response, Status};

use crate::utils;

pub mod email_service {
    tonic::include_proto!("email");
}

impl From<email_service::EmailUser> for lib::utils::models::EmailUser {
    fn from(user: email_service::EmailUser) -> Self {
        Self {
            full_name: Some(user.full_name), // Ensuring `Option<String>`
            email_address: user.email_address,
        }
    }
}

// impl From<lib::utils::models::EmailUser> for email_service::EmailUser {
//     fn from(user: lib::utils::models::EmailUser) -> Self {
//         Self {
//             full_name: user.full_name.unwrap_or_default(), // Convert Option<String> to String
//             email_address: user.email_address,
//         }
//     }
// }

impl From<email_service::Email> for lib::utils::models::Email {
    fn from(email: email_service::Email) -> Self {
        Self {
            recipient: email.recipient.map_or_else(
                || lib::utils::models::EmailUser {
                    full_name: None,
                    email_address: String::new(),
                },
                |user| user.into(), // Convert only if Some(user)
            ),
            subject: email.subject,
            title: email.title,
            body: email.body,
        }
    }
}

// impl From<lib::utils::models::Email> for email_service::Email {
//     fn from(email: lib::utils::models::Email) -> Self {
//         Self {
//             recipient: Some(email.recipient.into()), // Convert EmailUser back to email_service type
//             subject: email.subject,
//             title: email.title,
//             body: email.body,
//         }
//     }
// }

#[derive(Debug, Default)]
pub struct EmailServiceImplementation;

#[tonic::async_trait]
impl EmailService for EmailServiceImplementation {
    async fn send_email(
        &self,
        request: Request<email_service::Email>,
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

        let send_email_res = utils::email::send_email(&request.into_inner().into()).await;

        match send_email_res {
            Ok(send_email_res) => Ok(Response::new(EmailResponse {
                message: send_email_res.to_owned(),
            })),
            Err(e) => Err(e.into()),
        }
    }
}
