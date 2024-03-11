use async_graphql::{ComplexObject, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserProfessionalInfoInput")]
#[graphql(complex)]
pub struct UserProfessionalInfo {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub description: String,
    pub occupation: String,
    pub start_date: String,
}

#[ComplexObject]
impl UserProfessionalInfo {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}