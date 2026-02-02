use std::sync::Arc;

use async_graphql::{ComplexObject, Enum, InputObject, Object, OutputType, SimpleObject};
use axum::http::{HeaderName, HeaderValue};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;
use tokio::sync::Mutex;
use tonic::metadata::MetadataMap;

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
    pub new_access_token: Option<String>,
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

#[derive(Clone, Default)]
pub struct AxumAuthContext {
    pub request_headers: HeaderMap,
    pub response_headers: Arc<Mutex<HeaderMap>>,
}

pub enum MetadataView<'a> {
    Http(Option<&'a HeaderMap>),
    Grpc(Option<&'a MetadataMap>),
}

impl<'a> MetadataView<'a> {
    pub fn as_header_map(&self) -> Option<HeaderMap> {
        match self {
            MetadataView::Http(Some(headers)) => Some((*headers).clone()),
            MetadataView::Grpc(Some(metadata)) => {
                let mut header_map = HeaderMap::new();

                for key_and_value in metadata.iter() {
                    match key_and_value {
                        tonic::metadata::KeyAndValueRef::Ascii(key, value) => {
                            let header_name =
                                HeaderName::from_bytes(key.as_str().as_bytes()).ok()?;
                            let header_value = HeaderValue::from_str(value.to_str().ok()?).ok()?;
                            header_map.insert(header_name, header_value);
                        }
                        tonic::metadata::KeyAndValueRef::Binary(key, value) => {
                            let header_name =
                                HeaderName::from_bytes(key.as_str().as_bytes()).ok()?;
                            let bytes = value.to_bytes().ok()?;
                            let header_value = HeaderValue::from_bytes(&bytes).ok()?;
                            header_map.insert(header_name, header_value);
                        }
                    }
                }

                Some(header_map)
            }
            _ => None,
        }
    }
}

pub struct GrpcAuthContext {
    pub request_metadata: MetadataMap,
    pub response_metadata: Arc<Mutex<MetadataMap>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    data: T,
    metadata: ApiResponseMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ApiResponseMetadata {
    request_id: String,
    new_access_token: Option<String>,
}

impl<T: Sync + Send + Clone> ApiResponse<T> {
    pub fn new(data: &T, request_id: String, new_access_token: Option<String>) -> Self {
        Self {
            data: data.clone(),
            metadata: ApiResponseMetadata {
                request_id,
                new_access_token,
            },
        }
    }

    pub fn set_data(&mut self, new_data: T) -> &Self {
        self.data = new_data;
        self
    }

    pub fn set_metadata(
        &mut self,
        request_id: Option<String>,
        new_access_token: Option<String>,
    ) -> &Self {
        self.metadata = ApiResponseMetadata {
            request_id: request_id.unwrap_or(self.metadata.request_id.clone()),
            new_access_token,
        };
        self
    }

    pub fn get_data(&self) -> T {
        self.data.clone()
    }

    pub fn get_request_id(&self) -> String {
        self.metadata.request_id.clone()
    }

    pub fn get_new_access_token(&self) -> Option<String> {
        self.metadata.new_access_token.as_ref().cloned()
    }
}
