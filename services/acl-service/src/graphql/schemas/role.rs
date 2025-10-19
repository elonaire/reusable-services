use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use lib::utils::models::RoleType;
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct RoleInput {
    pub role_name: String,
    #[graphql(skip)]
    pub created_by: String,
    #[graphql(skip)]
    pub is_admin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct DepartmentUnder {
    pub id: String,
    pub body: DepartmentUnderBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct RoleMetadata {
    pub role_type: RoleType,
    pub organization_id: Option<String>,
    pub department_id: Option<String>,
    pub admin_permissions: Option<Vec<AdminPermission>>,
    // pub department_is_under: Option<DepartmentUnder>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum AdminPermission {
    #[graphql(name = "CreateOrganization")]
    CreateOrganization,
    #[graphql(name = "CreateDepartment")]
    CreateDepartment,
    #[graphql(name = "CreateRole")]
    CreateRole,
    #[graphql(name = "AssignRole")]
    AssignRole,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum DepartmentUnderBody {
    #[graphql(name = "Organization")]
    Organization,
    #[graphql(name = "Department")]
    Department,
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
    pub id: Option<Thing>,
    pub org_name: String,
    #[graphql(skip)]
    pub created_by: Option<Thing>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[ComplexObject]
impl Organization {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    async fn created_by(&self) -> String {
        self.created_by
            .as_ref()
            .map(|t| &t.id)
            .expect("created_by")
            .to_raw()
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
    pub id: Option<Thing>,
    pub dep_name: String,
    #[graphql(skip)]
    pub created_by: Option<Thing>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[ComplexObject]
impl Department {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    async fn created_by(&self) -> String {
        self.created_by
            .as_ref()
            .map(|t| &t.id)
            .expect("created_by")
            .to_raw()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct SystemRole {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub role_name: String,
    #[graphql(skip)]
    pub created_by: Option<Thing>,
}

#[ComplexObject]
impl SystemRole {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    async fn created_by(&self) -> String {
        self.created_by
            .as_ref()
            .map(|t| &t.id)
            .expect("created_by")
            .to_raw()
    }
}
