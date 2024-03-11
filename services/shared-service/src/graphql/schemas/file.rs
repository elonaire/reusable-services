use async_graphql::SimpleObject;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct TestResponse {
    pub message: String,
    // pub presigned_urls: Option<Vec<String>>,
    // pub upload_id: Option<String>,
    pub presigned_url: Option<String>,
}