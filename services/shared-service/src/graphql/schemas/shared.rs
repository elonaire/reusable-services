use std::collections::HashMap;

use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

pub type SurrealRelationQueryResponse<T> = HashMap<String, HashMap<String, Vec<T>>>;

// Reaction
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "ReactionInput")]
#[graphql(complex)]
pub struct Reaction {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub r#type: ReactionType,
}

// enum for ReactionType
#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum ReactionType {
    Like,
    Dislike,
    Love,
    Haha,
    Wow,
    Sad,
    Angry,
}

#[ComplexObject]
impl Reaction {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "MessageInput")]
#[graphql(complex)]
pub struct Message {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub subject: Subject,
    pub body: String,
    pub sender_name: String,
    pub sender_email: String,
    pub created_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum Subject {
    #[graphql(name = "JobOffer")]
    JobOffer,
    #[graphql(name = "Consultation")]
    Consultation,
    #[graphql(name = "Feedback")]
    Feedback,
    #[graphql(name = "Complaint")]
    Complaint,
    #[graphql(name = "Enquiry")]
    Enquiry,
    #[graphql(name = "Suggestion")]
    Suggestion,
}

#[ComplexObject]
impl Message {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}
