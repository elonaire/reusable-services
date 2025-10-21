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

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailMQTTPayload<'a> {
    pub recipient: &'a str,
    pub subject: &'a str,
    pub title: &'a str,
    pub template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminPrivilege {
    Admin,
    SuperAdmin,
}

impl TryFrom<i32> for AdminPrivilege {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AdminPrivilege::Admin),
            1 => Ok(AdminPrivilege::SuperAdmin),
            _ => Err("Invalid status"),
        }
    }
}

impl From<AdminPrivilege> for i32 {
    fn from(status: AdminPrivilege) -> Self {
        match status {
            AdminPrivilege::Admin => 0,
            AdminPrivilege::SuperAdmin => 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationConstraint {
    pub roles: Vec<String>,
    pub privilege: Option<AdminPrivilege>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum RoleType {
    #[graphql(name = "Admin")]
    Admin,
    #[graphql(name = "Other")]
    Other,
}
