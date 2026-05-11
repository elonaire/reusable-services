use async_graphql::{ComplexObject, InputObject, SimpleObject};
use chrono::{DateTime, Utc};
use lib::utils::models::AdminPrivilege;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct RoleInput {
    pub role_name: String,
    #[graphql(skip)]
    pub created_by: Option<RecordId>,
    #[graphql(skip)]
    pub is_admin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct RoleMetadata {
    pub admin_privilege: AdminPrivilege,
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
    pub permission_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct SystemRole {
    #[graphql(skip)]
    pub id: RecordId,
    pub role_name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: DateTime<Utc>,
    pub is_admin: Option<bool>,
    pub is_default: Option<bool>,
    pub is_super_admin: Option<bool>,
    pub updated_at: DateTime<Utc>,
}

#[ComplexObject]
impl SystemRole {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    async fn created_by(&self) -> Option<String> {
        match &self.created_by.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct OrganizationInput {
    pub org_name: String,
    #[graphql(skip)]
    pub created_by: Option<RecordId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct Organization {
    #[graphql(skip)]
    pub id: RecordId,
    pub org_name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[ComplexObject]
impl Organization {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    async fn created_by(&self) -> Option<String> {
        match &self.created_by.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct DepartmentInput {
    pub dep_name: String,
    #[graphql(skip)]
    pub created_by: Option<RecordId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct DepartmentMetadata {
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct Department {
    #[graphql(skip)]
    pub id: RecordId,
    pub dep_name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[ComplexObject]
impl Department {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    async fn created_by(&self) -> Option<String> {
        match &self.created_by.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct PermissionInput {
    pub name: String,
    #[graphql(skip)]
    pub created_by: Option<RecordId>,
    #[graphql(skip)]
    pub is_admin: bool,
    #[graphql(skip)]
    pub is_super_admin: bool,
    #[graphql(skip)]
    pub resource: Option<RecordId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct PermissionMetadata {
    pub admin_privilege: AdminPrivilege,
    pub resource_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[ComplexObject]
impl Permission {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    async fn created_by(&self) -> Option<String> {
        match &self.created_by.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct ResourceInput {
    pub name: String,
    #[graphql(skip)]
    pub created_by: Option<RecordId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct Resource {
    #[graphql(skip)]
    pub id: RecordId,
    pub name: String,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[ComplexObject]
impl Resource {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    async fn created_by(&self) -> Option<String> {
        match &self.created_by.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject, SurrealValue)]
pub struct ResourceMetadata {
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
}
