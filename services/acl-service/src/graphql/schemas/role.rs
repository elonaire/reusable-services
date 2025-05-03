use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

// #[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
// pub enum RoleName {
//     #[graphql(name = "User")]
//     User,
//     #[graphql(name = "Admin")]
//     Admin,
//     #[graphql(name = "Guest")]
//     Guest,
//     #[graphql(name = "SuperAdmin")]
//     SuperAdmin,
// }

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "RoleInput")]
pub struct SystemRole {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub role_name: String,
}

// #[ComplexObject]
// impl SystemRole {
//     async fn id(&self) -> String {
//         self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
//     }
// }
