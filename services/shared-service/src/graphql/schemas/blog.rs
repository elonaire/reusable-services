use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "BlogPostInput")]
#[graphql(complex)]
pub struct BlogPost {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub title: String,
    pub status: String,
    pub image: String,
    pub category: BlogCategory,
    pub link: String,
    pub published_date: Option<String>,
    pub author: String,
}

// enum for BlogCategory: "WebDevelopment", "MobileDevelopment", "AI", "Technology", "Lifestyle"
#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum BlogCategory {
    WebDevelopment,
    MobileDevelopment,
    ArtificialIntelligence,
    Technology,
    Lifestyle,
}

impl BlogCategory {
    pub fn to_string(&self) -> String {
        match self {
            BlogCategory::WebDevelopment => "WebDevelopment".to_string(),
            BlogCategory::MobileDevelopment => "MobileDevelopment".to_string(),
            BlogCategory::ArtificialIntelligence => "ArtificialIntelligence".to_string(),
            BlogCategory::Technology => "Technology".to_string(),
            BlogCategory::Lifestyle => "Lifestyle".to_string(),
        }
    }
}

// BlogComment
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "BlogCommentInput")]
#[graphql(complex)]
pub struct BlogComment {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub content: String,
    pub published_date: Option<String>,
}

#[ComplexObject]
impl BlogPost {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}

#[ComplexObject]
impl BlogComment {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}
