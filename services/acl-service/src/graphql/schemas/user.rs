use std::collections::HashMap;

use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

use crate::utils::auth::OAuthClientName;

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum Gender {
    #[graphql(name = "Male")]
    Male,
    #[graphql(name = "Female")]
    Female,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, Default)]
#[graphql(input_name = "UserInput")]
#[graphql(complex)]
pub struct User {
    #[graphql(skip)]
    pub id: Option<Thing>,
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
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
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
}

#[ComplexObject]
impl User {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
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
        // calculate age from &self.dob
        match &self.dob.as_ref() {
            Some(dob) => {
                let dob = DateTime::parse_from_rfc3339(dob).ok()?;
                let from_ymd = NaiveDate::from_ymd_opt(dob.year(), dob.month(), dob.day())?;
                let today = Utc::now().date_naive();
                today.years_since(from_ymd)
            }
            None => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct UserOutput {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub user_name: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub gender: Option<Gender>,
    pub dob: Option<String>,
    pub email: String,
    pub country: Option<String>,
    pub phone: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub status: Option<AccountStatus>,
    pub oauth_client: Option<OAuthClientName>,
    pub oauth_user_id: Option<String>,
    pub profile_picture: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
}

#[ComplexObject]
impl UserOutput {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
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
        // calculate age from &self.dob
        match &self.dob.as_ref() {
            Some(dob) => {
                let dob = DateTime::parse_from_rfc3339(dob).ok()?;
                let from_ymd = NaiveDate::from_ymd_opt(dob.year(), dob.month(), dob.day())?;
                let today = Utc::now().date_naive();
                today.years_since(from_ymd)
            }
            None => None,
        }
    }
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
    pub url: Option<String>,
    pub token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct DecodedGoogleOAuthToken {
    pub azp: String,
    pub aud: String,
    pub sub: String,
    pub scope: String,
    pub exp: String,
    pub expires_in: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUserInfo {
    pub resource_name: String,
    pub etag: String,
    pub email_addresses: Vec<GoogleUserEmailAddress>,
    pub names: Vec<GoogleUserName>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUserName {
    pub metadata: GoogleFieldMetadata,
    pub display_name: String,
    pub display_name_last_first: String,
    pub unstructured_name: String,
    pub family_name: String,
    pub given_name: String,
    pub middle_name: Option<String>,
    pub honorific_prefix: Option<String>,
    pub honorific_suffix: Option<String>,
    pub phonetic_full_name: Option<String>,
    pub phonetic_family_name: Option<String>,
    pub phonetic_given_name: Option<String>,
    pub phonetic_middle_name: Option<String>,
    pub phonetic_honorific_prefix: Option<String>,
    pub phonetic_honorific_suffix: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUserEmailAddress {
    pub metadata: GoogleFieldMetadata,
    pub value: String,
    pub r#type: Option<String>,
    pub formatted_type: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[serde(rename_all = "camelCase")]
pub struct GoogleFieldMetadata {
    pub primary: bool,
    pub source_primary: bool,
    pub verified: Option<bool>,
    pub source: GoogleSource,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[serde(rename_all = "camelCase")]
pub struct GoogleSource {
    pub r#type: GoogleSourceType,
    pub id: String,
    pub etag: Option<String>,
    pub update_time: Option<String>,
    pub profile_metadata: Option<GoogleUserProfileMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GoogleSourceType {
    SourceTypeUnspecified,
    Account,
    Profile,
    DomainProfile,
    Contact,
    OtherContact,
    DomainContact,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[serde(rename_all = "camelCase")]
pub struct GoogleUserProfileMetadata {
    pub object_type: GoogleUserObjectType,
    pub user_types: GoogleUserUserType,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GoogleUserObjectType {
    ObjectTypeUnspecified,
    Person,
    Page,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GoogleUserUserType {
    UserTypeUnknown,
    GoogleUser,
    GplusUser,
    GoogleAppsUser,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct GithubUserProfile {
    pub login: String,
    pub id: u64,
    pub node_id: String,
    pub avatar_url: String,
    pub gravatar_id: String,
    pub url: String,
    pub html_url: String,
    pub followers_url: String,
    pub following_url: String,
    pub gists_url: String,
    pub starred_url: String,
    pub subscriptions_url: String,
    pub organizations_url: String,
    pub repos_url: String,
    pub events_url: String,
    pub received_events_url: String,
    pub r#type: String,
    pub site_admin: bool,
    pub name: String,
    pub company: Option<String>,
    pub blog: Option<String>,
    pub location: Option<String>,
    pub email: Option<String>,
    pub hireable: Option<bool>,
    pub bio: Option<String>,
    pub twitter_username: Option<String>,
    pub public_repos: u64,
    pub public_gists: u64,
    pub followers: u64,
    pub following: u64,
    pub created_at: String,
    pub updated_at: String,
    pub private_gists: u64,
    pub total_private_repos: u64,
    pub owned_private_repos: u64,
    pub disk_usage: u64,
    pub collaborators: u64,
    pub two_factor_authentication: bool,
    pub plan: Plan,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct Plan {
    pub name: String,
    pub space: u64,
    pub collaborators: u64,
    pub private_repos: u64,
}

pub enum OAuthUser {
    Google(GoogleUserInfo),
    Github(GithubUserProfile),
}

// #[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
// #[graphql(input_name = "ProfessionInput")]
// pub struct Profession {
//     pub user_id: String,
//     pub occupation: String,
//     pub description: String,
//     pub start_date: String,
// }

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserUpdateInput")]
pub struct UserUpdate {
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
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

pub type SurrealRelationQueryResponse<T> = HashMap<String, Vec<T>>;
