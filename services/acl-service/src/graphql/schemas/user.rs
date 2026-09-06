use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use chrono::{DateTime, Utc};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};

use crate::utils::auth::OAuthClientName;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPlatform {
    Web,
    Native, // iOS / Android / desktop — no cookie jar shared with your backend
}

impl ClientPlatform {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        match headers
            .get("x-client-platform")
            .and_then(|v| v.to_str().ok())
        {
            Some("native") => ClientPlatform::Native,
            _ => ClientPlatform::Web,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq, SurrealValue)]
pub enum Gender {
    #[graphql(name = "Male")]
    Male,
    #[graphql(name = "Female")]
    Female,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq, Default, SurrealValue,
)]
pub enum AccountStatus {
    #[graphql(name = "Active")]
    Active,
    #[default]
    #[graphql(name = "Inactive")]
    Inactive,
    #[graphql(name = "Suspended")]
    Suspended,
    #[graphql(name = "Deleted")]
    Deleted,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, Default, SimpleObject, InputObject, SurrealValue,
)]
#[graphql(input_name = "UserSocialInput")]
pub struct UserSocial {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, InputObject, Default, SurrealValue)]
pub struct UserInput {
    pub user_name: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub gender: Option<Gender>,
    pub dob: Option<String>,
    pub email: String,
    pub country: Option<String>,
    pub phone: Option<String>,
    #[graphql(secret)]
    pub password: String,
    #[graphql(skip)]
    pub status: AccountStatus,
    #[graphql(skip)]
    pub oauth_client: Option<OAuthClientName>,
    #[graphql(skip)]
    pub oauth_user_id: Option<String>,
    pub profile_picture: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
    pub socials: Option<Vec<UserSocial>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct User {
    #[graphql(skip, secret)]
    pub id: RecordId,
    pub user_name: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub gender: Option<Gender>,
    pub dob: Option<DateTime<Utc>>,
    pub email: String,
    pub country: Option<String>,
    pub phone: Option<String>,
    #[graphql(secret)]
    pub password: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: Option<AccountStatus>,
    pub oauth_client: Option<OAuthClientName>,
    pub oauth_user_id: Option<String>,
    pub profile_picture: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
    pub socials: Option<Vec<UserSocial>>,
}

#[ComplexObject]
impl User {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    async fn full_name(&self) -> String {
        format!(
            "{} {} {}",
            self.first_name.as_ref().unwrap_or(&"".to_string()),
            self.middle_name.as_ref().unwrap_or(&"".to_string()),
            self.last_name.as_ref().unwrap_or(&"".to_string())
        )
    }

    async fn age(&self) -> Option<u32> {
        let dob = self.dob.as_ref()?.date_naive();
        let today = Utc::now().date_naive();

        today.years_since(dob)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, InputObject, Default, SurrealValue)]
pub struct FetchUsersQueryFilters {
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
    pub role_id: Option<String>,
    pub status: Option<AccountStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserLoginsInput")]
pub struct UserLogins {
    pub user_name: Option<String>,
    #[graphql(secret)]
    pub password: Option<String>,
    pub oauth_client: Option<OAuthClientName>,
}

impl UserLogins {
    pub fn transformed(&self) -> Self {
        let (user_name, password, oauth_client) =
            if self.password.is_some() && self.user_name.is_some() {
                (self.user_name.clone(), self.password.clone(), None)
            } else {
                (None, None, self.oauth_client)
            };

        UserLogins {
            user_name,
            password,
            oauth_client,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct AuthDetails {
    pub token: Option<String>,
    pub url: Option<String>,
    pub encrypted_state: Option<String>, // native OAuth: csrf/state to echo back on callback
    pub refresh_token: Option<String>, // native password login: RSA-encrypted, same as the cookie value
    pub oauth_client: Option<OAuthClientName>, // native same as the cookie value "oauth_client=<this>"
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
// #[serde(rename_all = "camelCase")]
pub struct GoogleUserInfo {
    pub sub: String, // use this as your stable user ID
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<bool>,
    pub given_name: Option<String>,  // first name
    pub family_name: Option<String>, // last name
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct GithubUserProfile {
    pub id: u64, // stable unique user ID (equivalent to Google's sub)
    pub email: Option<String>,
    pub name: Option<String>, // full name only, no first/last split
    pub avatar_url: String,
}

pub enum OAuthUser {
    Google(GoogleUserInfo),
    Github(GithubUserProfile),
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
#[graphql(input_name = "UserUpdateInput")]
pub struct UserUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<Gender>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[graphql(secret)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthTokenPair {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, InputObject, SurrealValue)]
pub struct ApiKeyInput {
    #[graphql(skip)]
    pub owner: Option<RecordId>,
    #[graphql(skip)]
    pub key_prefix: String,
    #[graphql(skip)]
    pub secret_hash: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, InputObject, SurrealValue)]
pub struct ApiKeyInputMetadata {
    pub role_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct ApiKey {
    #[graphql(skip)]
    pub id: RecordId,
    pub owner: User,
    pub key_prefix: String,
    pub secret_hash: String,
    pub name: String,
    pub status: ApiKeyStatus,
    pub last_used_at: Option<String>,
    pub last_used_ip: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Enum, Copy, SurrealValue)]
pub enum ApiKeyStatus {
    #[graphql(name = "Active")]
    Active,
    #[graphql(name = "Revoked")]
    Revoked,
}

#[ComplexObject]
impl ApiKey {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}
