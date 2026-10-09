use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use chrono::{DateTime, Utc};
use lib::utils::models::UserId;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct UploadedFile {
    #[graphql(skip)]
    pub id: RecordId,
    pub name: String,
    pub size: u64,
    pub mime_type: String,
    pub system_filename: String,
    pub is_premium: bool,
    pub is_public: bool,
    pub owner: UserId,
    pub created_at: DateTime<Utc>,
}

#[ComplexObject]
impl UploadedFile {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct UploadedFileResponse {
    pub field_name: String,
    pub file_id: String,
    pub file_name: String,
    pub original_filename: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct Bucket {
    #[graphql(skip)]
    pub id: RecordId,
    pub name: String,
    pub owner: UserId,
    pub is_public: bool,
    pub storage_class: StorageClass,
    pub created_at: DateTime<Utc>,
    pub is_premium: bool,
}

#[ComplexObject]
impl Bucket {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct Key {
    #[graphql(skip)]
    pub id: RecordId,
    pub name: String,
    pub owner: UserId,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
}

#[ComplexObject]
impl Key {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Enum, SurrealValue)]
pub enum StorageClass {
    #[graphql(name = "Standard")]
    Standard,
    #[graphql(name = "Nearline")]
    Nearline,
    #[graphql(name = "Coldline")]
    Coldline,
    #[graphql(name = "Archive")]
    Archive,
}

impl Default for StorageClass {
    fn default() -> Self {
        StorageClass::Standard
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, InputObject, SurrealValue)]
pub struct BucketInput {
    pub name: String,
    #[graphql(skip)]
    pub owner: Option<RecordId>,
    pub is_public: Option<bool>,
    pub is_premium: Option<bool>,
    pub storage_class: Option<StorageClass>,
}

#[derive(Debug, Serialize, Deserialize, Clone, InputObject, SurrealValue)]
pub struct KeyInput {
    pub name: String,
    #[graphql(skip)]
    pub owner: Option<RecordId>,
    pub is_public: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, InputObject, SurrealValue)]
pub struct KeyInputMetadata {
    pub key_id: Option<String>,
    pub bucket_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedContainer {
    pub bucket: RecordId,
    pub key: Option<RecordId>, // innermost key, None if attached directly to bucket
    pub bucket_is_premium: bool,
    pub bucket_is_public: bool,
}

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub mime_type: String,
    pub system_filename: String,
    pub is_premium: bool,
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UploadStatus {
    InProgress,
    Completed,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSession {
    pub id: RecordId,
    pub user: RecordId,
    pub upload_id: String,
    pub file_name: String,
    pub total_size: i64,
    pub mime_type: String,
    pub bucket: RecordId,
    pub key: Option<RecordId>,
    pub part_size: i64,
    pub total_parts: i64,
    pub status: UploadStatus,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
