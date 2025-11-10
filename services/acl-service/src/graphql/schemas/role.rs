use async_graphql::{ComplexObject, InputObject, SimpleObject};
use lib::utils::models::AdminPrivilege;
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
    pub admin_privilege: AdminPrivilege,
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
    pub permission_ids: Option<Vec<String>>,
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
pub struct DepartmentMetadata {
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

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct PermissionInput {
    pub name: String,
    #[graphql(skip)]
    pub created_by: String,
    #[graphql(skip)]
    pub is_admin: bool,
    #[graphql(skip)]
    pub is_super_admin: bool,
    pub resource: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct PermissionMetadata {
    pub admin_privilege: AdminPrivilege,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct Permission {
    #[graphql(skip)]
    pub id: RecordId,
    pub name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub resource: Resource,
    pub is_admin: bool,
    pub is_super_admin: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[ComplexObject]
impl Permission {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }

    async fn created_by(&self) -> String {
        self.created_by.key().to_string()
    }

    // async fn resource(&self) -> String {
    //     self.created_by.key().to_string()
    // }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct ResourceInput {
    pub name: String,
    #[graphql(skip)]
    pub created_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct Resource {
    #[graphql(skip)]
    pub id: RecordId,
    pub name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[ComplexObject]
impl Resource {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }

    async fn created_by(&self) -> String {
        self.created_by.key().to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct ResourceMetadata {
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
}
