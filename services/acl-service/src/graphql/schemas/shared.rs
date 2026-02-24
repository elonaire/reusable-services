use async_graphql::{OutputType, SimpleObject};
use lib::utils::models::{ApiResponse, AuthStatus};

use crate::graphql::schemas::{
    role::{Department, Organization, Permission, Resource, SystemRole},
    user::{AuthDetails, User},
};

type Users = Vec<User>;
type SystemRoles = Vec<SystemRole>;
type Permissions = Vec<Permission>;
type Organizations = Vec<Organization>;
type Departments = Vec<Department>;
type Resources = Vec<Resource>;

#[derive(SimpleObject)]
#[graphql(concrete(name = "UserResponse", params(User)))]
#[graphql(concrete(name = "UsersResponse", params(Users)))]
#[graphql(concrete(name = "SystemRoleResponse", params(SystemRole)))]
#[graphql(concrete(name = "SystemRolesResponse", params(SystemRoles)))]
#[graphql(concrete(name = "AuthDetailsResponse", params(AuthDetails)))]
#[graphql(concrete(name = "PermissionResponse", params(Permission)))]
#[graphql(concrete(name = "PermissionsResponse", params(Permissions)))]
#[graphql(concrete(name = "ResourceResponse", params(Resource)))]
#[graphql(concrete(name = "ResourcesResponse", params(Resources)))]
#[graphql(concrete(name = "DepartmentResponse", params(Department)))]
#[graphql(concrete(name = "DepartmentsResponse", params(Departments)))]
#[graphql(concrete(name = "OrganizationResponse", params(Organization)))]
#[graphql(concrete(name = "OrganizationsResponse", params(Organizations)))]
#[graphql(concrete(name = "BoolResponse", params(bool)))]
#[graphql(concrete(name = "AuthStatusResponse", params(AuthStatus)))]
pub struct GraphQLApiResponse<T: OutputType> {
    pub data: T,
    pub metadata: GraphQLApiResponseMetadata,
}

#[derive(SimpleObject)]
pub struct GraphQLApiResponseMetadata {
    pub request_id: String,
    pub new_access_token: Option<String>,
}

impl<T: Send + Sync + Clone + OutputType> From<ApiResponse<T>> for GraphQLApiResponse<T> {
    fn from(standard_res: ApiResponse<T>) -> Self {
        Self {
            data: standard_res.get_data(),
            metadata: GraphQLApiResponseMetadata {
                request_id: standard_res.get_request_id(),
                new_access_token: standard_res.get_new_access_token(),
            },
        }
    }
}
