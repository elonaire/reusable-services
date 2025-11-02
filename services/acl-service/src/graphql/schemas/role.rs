use async_graphql::{ComplexObject, InputObject, SimpleObject};
use lib::utils::models::RoleType;
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct RoleInput {
    pub role_name: String,
    #[graphql(skip)]
    pub created_by: String,
    #[graphql(skip)]
    pub is_admin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct RoleMetadata {
    pub role_type: RoleType,
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
    pub permission_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct OrganizationInput {
    pub org_name: String,
    #[graphql(skip)]
    pub created_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct Organization {
    #[graphql(skip)]
    pub id: RecordId,
    pub org_name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[ComplexObject]
impl Organization {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }

    async fn created_by(&self) -> String {
        self.created_by.key().to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct DepartmentInput {
    pub dep_name: String,
    #[graphql(skip)]
    pub created_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct DepartmentInputMetadata {
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct Department {
    #[graphql(skip)]
    pub id: RecordId,
    pub dep_name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[ComplexObject]
impl Department {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }

    async fn created_by(&self) -> String {
        self.created_by.key().to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct SystemRole {
    #[graphql(skip)]
    pub id: RecordId,
    pub role_name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: Option<String>,
    pub is_admin: Option<bool>,
    pub is_default: Option<bool>,
    pub is_super_admin: Option<bool>,
    pub updated_at: Option<String>,
}

#[ComplexObject]
impl SystemRole {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }

    async fn created_by(&self) -> String {
        self.created_by.key().to_string()
    }
}
