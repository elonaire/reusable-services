use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use surrealdb::sql::{Datetime, Thing};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "BlogPostInput")]
#[graphql(complex)]
pub struct BlogPost {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub title: String,
    pub short_description: String,
    pub status: Option<String>,
    pub image: String,
    pub category: BlogCategory,
    pub link: String,
    pub published_date: Option<String>,
    #[graphql(skip)]
    pub created_at: Datetime,
    pub author: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlogPostInputWithSurrealDatetime {
    pub title: String,
    pub short_description: String,
    pub status: Option<String>,
    pub image: String,
    pub category: BlogCategory,
    pub link: String,
    pub published_date: Option<DateTime<FixedOffset>>,
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
    #[graphql(skip)]
    pub created_at: Datetime,
}

#[ComplexObject]
impl BlogPost {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    // use the link field to generate HTML content from a markdown file with the name equal to the link field value
    // e.g. if link is "my-first-blog-post", the content will be read from "posts/my-first-blog-post.md"
    // On live server, the markdown files might be stored on AWS S3 or other cloud storage services
    async fn content(&self) -> String {
        let content =
            std::fs::read_to_string(format!("src/posts/{}.md", self.link)).expect("content");
        println!("content: {:?}", content);
        let html_content = markdown::to_html(&content);
        html_content
    }

    // convert date_created from Surreal Datetime to String
    async fn created_at(&self) -> String {
        self.created_at.to_rfc3339()
    }

    // async fn published_date(&self) -> String {
    //     self.published_date.as_ref().map(|t| t.to_rfc3339()).expect("published_date")
    // }
}

#[ComplexObject]
impl BlogComment {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}
