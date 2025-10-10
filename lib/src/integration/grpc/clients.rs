use crate::utils::{self, models::AdminPrivilege};

// should match the package name in the .proto file
pub mod acl_service {
    include!("out/acl.rs");
}

// should match the package name in the .proto file
pub mod email_service {
    include!("out/email.rs");
}

// should match the package name in the .proto file
pub mod files_service {
    include!("out/files.rs");
}

/// For easy conversion to protobuf
impl From<utils::models::AuthStatus> for acl_service::ConfirmAuthenticationResponse {
    fn from(auth_status: utils::models::AuthStatus) -> Self {
        Self {
            sub: auth_status.sub,
            is_auth: auth_status.is_auth,
            current_role: auth_status.current_role,
        }
    }
}

/// For easy conversion to protobuf
impl From<acl_service::AuthStatus> for utils::models::AuthStatus {
    fn from(auth_status: acl_service::AuthStatus) -> Self {
        Self {
            sub: auth_status.sub,
            is_auth: auth_status.is_auth,
            current_role: auth_status.current_role,
        }
    }
}

/// For easy conversion to protobuf
impl From<acl_service::AuthorizationConstraint> for utils::models::AuthorizationConstraint {
    fn from(authorization_constraint: acl_service::AuthorizationConstraint) -> Self {
        Self {
            roles: authorization_constraint.roles,
            privilege: Some(
                authorization_constraint
                    .privilege
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
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
impl From<email_service::SendEmailRequest> for utils::models::Email {
    fn from(email: email_service::SendEmailRequest) -> Self {
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

impl From<files_service::PurchaseFileRequest> for utils::models::PurchaseFileDetails {
    fn from(file_details: files_service::PurchaseFileRequest) -> Self {
        Self {
            file_id: file_details.file_id, // Ensuring `Option<String>`
            buyer_id: file_details.buyer_id,
        }
    }
}
