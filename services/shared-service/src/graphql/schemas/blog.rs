use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
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
    pub is_featured: bool,
    pub is_premium: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "BlogPostUpdateInput")]
pub struct BlogPostUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<BlogCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_featured: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_premium: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// enum for BlogCategory: "WebDevelopment", "MobileDevelopment", "AI", "Technology", "Lifestyle"
#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum BlogCategory {
    #[graphql(name="WebDevelopment")]
    WebDevelopment,
    #[graphql(name="MobileDevelopment")]
    MobileDevelopment,
    #[graphql(name="ArtificialIntelligence")]
    ArtificialIntelligence,
    #[graphql(name="Technology")]
    Technology,
    #[graphql(name="Lifestyle")]
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
        let blog_posts_dir: String = std::env::var("BLOG_POSTS_DIR").expect("POSTS_DIR not set");

        let content =
            std::fs::read_to_string(format!("{}{}.md", blog_posts_dir, self.link)).expect("content");
        
        let html_content = markdown::to_html(&content);
        html_content
    }
}

#[ComplexObject]
impl BlogComment {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}

