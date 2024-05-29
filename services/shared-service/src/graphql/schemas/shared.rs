use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

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
