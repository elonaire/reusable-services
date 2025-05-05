use async_graphql::{InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "RoleInput")]
pub struct SystemRole {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub role_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminPrivilege {
    Admin,
    SuperAdmin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationConstraint {
    pub roles: Vec<String>,
    pub privilege: Option<AdminPrivilege>,
}
