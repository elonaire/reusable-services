use async_graphql::{InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct User {
    #[graphql(skip)]
    pub id: Option<Thing>,
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
#[graphql(input_name = "UserLoginsInput")]
pub struct UserLogins {
    #[serde(rename = "userName")]
    pub user_name: Option<String>,
    #[graphql(secret)]
    pub password: Option<String>,
    // pub oauth_client: Option<OAuthClientName>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct AuthDetails {
    // pub url: Option<String>,
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignInResponse {
    #[serde(rename = "signIn")]
    pub sign_in: AuthDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginsVar {
    #[serde(rename = "rawUserDetails")]
    pub raw_user_details: UserLogins,
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
#[derive(Debug, Serialize, Deserialize)]
pub struct SendEmailVar {
    pub email: Email,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendEmailResponse {
    #[serde(rename = "sendEmail")]
    pub send_email: String,
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
