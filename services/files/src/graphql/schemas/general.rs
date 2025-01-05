use async_graphql::{ComplexObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct UploadedFile {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub name: String,
    pub size: u64,
    pub mime_type: String,
    pub system_filename: String,
    pub is_free: bool,
    pub created_at: Option<String>,
}

#[ComplexObject]
impl UploadedFile {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct UploadedFileResponse {
    pub field_name: String,
    pub file_id: String,
}
