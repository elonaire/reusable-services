use async_graphql::{SimpleObject, ComplexObject, InputObject, Enum};
use serde::{Serialize, Deserialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum RoleName {
    User,
    Admin,
    Guest
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "RoleInput")]
pub struct SystemRole {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub role_name: RoleName,
}

#[ComplexObject]
impl SystemRole {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}
