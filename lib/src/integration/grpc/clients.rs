use crate::utils;

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

pub mod payments_service {
    include!("out/payments.rs");
}

impl TryFrom<payments_service::UserPaymentDetails> for utils::models::UserPaymentDetails {
    type Error = anyhow::Error; // or your own error type

    fn try_from(
        payment_details: payments_service::UserPaymentDetails,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            email: payment_details.email,
            amount: payment_details.amount,
            reference: payment_details.reference,
            currency: payment_details.currency,
            metadata: payment_details
                .metadata
                .ok_or_else(|| anyhow::anyhow!("metadata is required for payment processing"))?
                .into(),
        })
    }
}

/// For easy conversion to protobuf
impl From<payments_service::PaymentDetailsMetadata> for utils::models::PaymentDetailsMetadata {
    fn from(metadata: payments_service::PaymentDetailsMetadata) -> Self {
        Self {
            resource: metadata.resource,
        }
    }
}

/// For easy conversion to protobuf
impl From<utils::models::AuthStatus> for acl_service::ConfirmAuthenticationResponse {
    fn from(auth_status: utils::models::AuthStatus) -> Self {
        Self {
            sub: auth_status.sub,
            is_auth: auth_status.is_auth,
            current_role: auth_status.current_role,
            new_access_token: auth_status.new_access_token,
            current_role_permissions: auth_status.current_role_permissions,
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
            new_access_token: auth_status.new_access_token,
            current_role_permissions: auth_status.current_role_permissions,
        }
    }
}

impl From<utils::models::AuthStatus> for acl_service::AuthStatus {
    fn from(auth_status: utils::models::AuthStatus) -> Self {
        Self {
            sub: auth_status.sub,
            is_auth: auth_status.is_auth,
            current_role: auth_status.current_role,
            new_access_token: auth_status.new_access_token,
            current_role_permissions: auth_status.current_role_permissions,
        }
    }
}

/// For easy conversion to protobuf
impl From<acl_service::AuthorizationConstraint> for utils::models::AuthorizationConstraint {
    fn from(authorization_constraint: acl_service::AuthorizationConstraint) -> Self {
        Self {
            permissions: authorization_constraint.permissions,
        }
    }
}

/// For easy conversion to protobuf
impl From<utils::models::AuthorizationConstraint> for acl_service::AuthorizationConstraint {
    fn from(authorization_constraint: utils::models::AuthorizationConstraint) -> Self {
        Self {
            permissions: authorization_constraint.permissions,
        }
    }
}

/// For easy conversion to protobuf
impl From<email_service::EmailUser> for utils::models::EmailUser {
    fn from(user: email_service::EmailUser) -> Self {
        Self {
            full_name: user.full_name,
            email_address: user.email_address,
        }
    }
}

/// For easy conversion to protobuf
impl TryFrom<email_service::SendEmailRequest> for utils::models::Email {
    type Error = anyhow::Error;

    fn try_from(email: email_service::SendEmailRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            recipient: email
                .recipient
                .ok_or_else(|| anyhow::anyhow!("recipient is required for sending email"))?
                .into(),
            subject: email.subject,
            title: email.title,
            body: email.body,
        })
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

/// For easy conversion to protobuf
impl From<acl_service::ConfirmAuthenticationResponse> for utils::models::AuthStatus {
    fn from(auth_status: acl_service::ConfirmAuthenticationResponse) -> Self {
        Self {
            sub: auth_status.sub,
            is_auth: auth_status.is_auth,
            current_role: auth_status.current_role,
            new_access_token: auth_status.new_access_token,
            current_role_permissions: auth_status.current_role_permissions,
        }
    }
}

/// For easy conversion to protobuf
impl From<files_service::CreateFileFromContentRequest> for utils::models::CreateFileInfo {
    fn from(file_info: files_service::CreateFileFromContentRequest) -> Self {
        Self {
            extension: file_info.extension.try_into().unwrap(),
            content: file_info.content,
            file_name: file_info.file_name,
            is_free: file_info.is_free,
        }
    }
}
