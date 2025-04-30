use crate::utils;

// should match the package name in the .proto file
pub mod acl_service {
    tonic::include_proto!("acl");
}

// should match the package name in the .proto file
pub mod email_service {
    tonic::include_proto!("email");
}

// should match the package name in the .proto file
pub mod files_service {
    tonic::include_proto!("files");
}

/// For easy conversion to protobuf
impl From<utils::models::AuthStatus> for acl_service::AuthStatus {
    fn from(auth_status: utils::models::AuthStatus) -> Self {
        Self {
            sub: auth_status.sub,
            is_auth: auth_status.is_auth,
        }
    }
}

/// For easy conversion to protobuf
impl From<email_service::EmailUser> for utils::models::EmailUser {
    fn from(user: email_service::EmailUser) -> Self {
        Self {
            full_name: Some(user.full_name), // Ensuring `Option<String>`
            email_address: user.email_address,
        }
    }
}

/// For easy conversion to protobuf
impl From<email_service::Email> for utils::models::Email {
    fn from(email: email_service::Email) -> Self {
        Self {
            recipient: email.recipient.map_or_else(
                || utils::models::EmailUser {
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

impl From<files_service::PurchaseFileDetails> for utils::models::PurchaseFileDetails {
    fn from(file_details: files_service::PurchaseFileDetails) -> Self {
        Self {
            file_id: file_details.file_id, // Ensuring `Option<String>`
            buyer_id: file_details.buyer_id,
        }
    }
}
