use async_graphql::{Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct RoleInput {
    pub role_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct DepartmentUnder {
    pub id: String,
    pub body: DepartmentUnderBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct RoleMetadata {
    pub role_type: RoleType,
    pub organization: Option<OrganizationInput>,
    pub department: Option<DepartmentInput>,
    pub admin_permissions: Option<Vec<AdminPermission>>,
    pub department_is_under: Option<DepartmentUnder>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct Organization {
    pub org_name: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct DepartmentInput {
    pub dep_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct Department {
    pub dep_name: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum RoleType {
    #[graphql(name = "Admin")]
    Admin,
    #[graphql(name = "Other")]
    Other,
}
