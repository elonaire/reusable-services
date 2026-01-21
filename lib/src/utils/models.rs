use async_graphql::{Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct User {
    #[graphql(skip)]
    pub id: RecordId,
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForeignKey {
    pub table: String,
    pub column: String,
    pub foreign_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct AuthStatus {
    #[serde(rename = "isAuth")]
    pub is_auth: bool,
    pub sub: String,
    pub current_role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct EmailUser {
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
    #[serde(rename = "emailAddress")]
    pub email_address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "EmailInput")]
pub struct Email {
    pub recipient: EmailUser,
    pub subject: String,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct PurchaseFileDetails {
    pub file_id: String,
    pub buyer_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct CreateFileInfo {
    pub file_name: String,
    pub content: String,
    pub extension: AllowedCreateFileExtension,
    pub is_free: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Enum, Copy, Eq)]
pub enum AllowedCreateFileExtension {
    #[graphql(name = "Markdown")]
    Markdown,
    #[graphql(name = "Txt")]
    Txt,
}

impl AllowedCreateFileExtension {
    pub fn fetch_mime_type(&self) -> &'static str {
        match self {
            Self::Markdown => "text/markdown",
            Self::Txt => "text/plain",
        }
    }
}

impl TryFrom<i32> for AllowedCreateFileExtension {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AllowedCreateFileExtension::Markdown),
            1 => Ok(AllowedCreateFileExtension::Txt),
            _ => Err("Invalid extension"),
        }
    }
}

impl From<AllowedCreateFileExtension> for i32 {
    fn from(status: AllowedCreateFileExtension) -> Self {
        match status {
            AllowedCreateFileExtension::Markdown => 0,
            AllowedCreateFileExtension::Txt => 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailMQTTPayload<'a> {
    pub recipient: &'a str,
    pub subject: &'a str,
    pub title: &'a str,
    pub template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Enum, Copy, Eq)]
pub enum AdminPrivilege {
    #[graphql(name = "Admin")]
    Admin,
    #[graphql(name = "SuperAdmin")]
    SuperAdmin,
    #[graphql(name = "None")]
    None,
}

impl TryFrom<i32> for AdminPrivilege {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AdminPrivilege::Admin),
            1 => Ok(AdminPrivilege::SuperAdmin),
            2 => Ok(AdminPrivilege::None),
            _ => Err("Invalid privilege"),
        }
    }
}

impl From<AdminPrivilege> for i32 {
    fn from(status: AdminPrivilege) -> Self {
        match status {
            AdminPrivilege::Admin => 0,
            AdminPrivilege::SuperAdmin => 1,
            AdminPrivilege::None => 2,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationConstraint {
    pub permissions: Vec<String>,
    pub privilege: AdminPrivilege,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct InitializePaymentResponse {
    pub status: bool,
    pub message: String,
    pub data: InitializePaymentResponseData,
}
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct InitializePaymentResponseData {
    #[serde(rename = "authorization_url")]
    pub authorization_url: String,
    #[serde(rename = "access_code")]
    pub access_code: String,
    pub reference: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserPaymentDetailsInput")]
pub struct UserPaymentDetails {
    pub email: String,
    pub amount: u64,
    // pub currency: Option<String>,
    pub reference: String,
    // pub metadata: Option<PaymentDetailsMetaData>,
}
