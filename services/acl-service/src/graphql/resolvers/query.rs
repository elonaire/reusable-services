use std::sync::Arc;

use async_graphql::{Context, Object, Result};
use axum::Extension;
use hyper::{
    header::{AUTHORIZATION, COOKIE},
    HeaderMap, StatusCode,
};
use lib::utils::{
    custom_error::ExtendedError,
    models::{AdminPrivilege, AuthStatus, AuthorizationConstraint},
};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::{
        role::{Department, Organization, SystemRole},
        user::{FetchUsersQueryFilters, User},
    },
    utils::auth::{confirm_authentication, confirm_authorization},
};

pub struct Query;

#[Object]
impl Query {
    /// Fetches a list of users based on hierarchy(default) or the provided filters.
    async fn fetch_users(
        &self,
        ctx: &Context<'_>,
        filters: Option<FetchUsersQueryFilters>,
    ) -> Result<Vec<User>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            roles: vec![],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, authenticated_ref, authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut fetch_users_query = db
            .query(
                r#"
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);
                IF !$user.exists()
               	{
              		THROW 'Invalid Input';
               	}
                                ;
                                RETURN IF $filters != NONE
               	{
              		RETURN IF $filters.organization_id != NONE
             			{

                				LET $organization = type::thing('organization', $filters.organization_id);

                				IF !$organization.exists()
               					{
              						THROW 'Invalid Input';
               					}
                				;

                				(SELECT * FROM user WHERE ->assigned->role->is_under->(organization WHERE id = $organization AND created_by = $user));

                                }
              		ELSE IF $filters.role_id != NONE
             			{

                				LET $role = type::thing('role', $filters.role_id);

                				IF !$role.exists()
               					{
              						THROW 'Invalid Input';
               					}
                				;

                				(SELECT * FROM user WHERE ->assigned->(role WHERE id = $role AND created_by = $user));

                                }
              		ELSE IF $filters.department_id != NONE
             			{

                				LET $department = type::thing('department', $filters.department_id);

                				IF !$department.exists()
               					{
              						THROW 'Invalid Input';
               					}
                				;

                				(SELECT * FROM user WHERE ->assigned->role->is_under->(department WHERE id = $department AND created_by = $user));

                                }
              		ELSE IF $filters.status != NONE
             			{ (SELECT * FROM user WHERE ->assigned->role->is_under->(organization WHERE created_by = $user) AND status = $filters.status) }
              		;
               	}
                                ELSE
               	{ <set>array::flatten([(SELECT * FROM user WHERE ->assigned->role->is_under->(organization WHERE created_by = $user)), (SELECT * FROM user WHERE ->assigned->role->is_under->(department WHERE created_by = $user)), (SELECT * FROM user WHERE ->assigned->role->is_under->department->is_under->(organization WHERE created_by = $user)), (SELECT * FROM user WHERE ->assigned->role->is_under->department->is_under->(department WHERE created_by = $user)), (SELECT * FROM user WHERE ->assigned->(role WHERE created_by = $user))]) }
                ;
                COMMIT TRANSACTION;
                "#
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .bind(("filters", filters))
            .await
            .map_err(|e| {
            tracing::error!("Error fetching users: {}", e);
            ExtendedError::new("Error fetching users", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        let response: Vec<User> = fetch_users_query.take(0).map_err(|e| {
            tracing::debug!("Users deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        Ok(response)
    }

    /// Fetch a single user by ID. Respects hierarchy and permissions.
    async fn fetch_single_user(&self, ctx: &Context<'_>, user_id: String) -> Result<User> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        match ctx.data_opt::<HeaderMap>() {
            Some(header_map) => {
                let auth_header = header_map.get(AUTHORIZATION);
                let cookie_header = header_map.get(COOKIE);

                if auth_header.is_none() || cookie_header.is_none() {
                    let mut user_query = db
                        .query(
                            "
                            BEGIN TRANSACTION;
                            LET $user = type::thing('user', $user_id);
                            LET $found_user = (SELECT id, first_name, middle_name, last_name, full_name, dob, email, country, profile_picture, bio, website, address FROM ONLY $user LIMIT 1);
                            RETURN $found_user;
                            COMMIT TRANSACTION;
                            "
                        )
                        .bind(("user_id", user_id))
                        .await
                        .map_err(|e| {
                        tracing::error!("Error fetching user: {}", e);
                        ExtendedError::new("Error fetching user", StatusCode::BAD_REQUEST.as_str()).build()
                    })?;

                    let user: Option<User> = user_query.take(0).map_err(|e| {
                        tracing::debug!("User deserialization error: {}", e);
                        ExtendedError::new(
                            "Server Error",
                            StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                        )
                        .build()
                    })?;

                    match user {
                        Some(user) => return Ok(user),
                        None => {
                            return Err(ExtendedError::new(
                                "User not found",
                                StatusCode::NOT_FOUND.as_str(),
                            )
                            .build())
                        }
                    }
                }

                let authenticated = confirm_authentication(Some(header_map), db).await?;

                let authenticated_ref = &authenticated;

                let authorization_constraint = AuthorizationConstraint {
                    roles: vec![],
                    privilege: Some(AdminPrivilege::Admin),
                };

                let authorized =
                    confirm_authorization(db, &authenticated, authorization_constraint).await?;
                let is_owner = authenticated_ref.sub.to_owned() == user_id;

                if !authorized && !is_owner {
                    return Err(
                        ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                    );
                }

                let mut user_query = db
                    .query(
                        "
                        BEGIN TRANSACTION;
                        LET $user = type::thing('user', $user_id);
                        LET $found_user = (SELECT * FROM ONLY $user LIMIT 1);
                        RETURN $found_user;
                        COMMIT TRANSACTION;
                        "
                    )
                    .query(
                        "
                        BEGIN TRANSACTION;
                        LET $user = type::thing('user', $user_id);
                        LET $auth_user = type::thing('user', $auth_sub);
                        LET $found_user = (SELECT * FROM ONLY $user WHERE (->assigned->(role WHERE created_by = $auth_user) OR ->assigned->role->is_under->(organization WHERE created_by = $auth_user) OR ->assigned->role->is_under->(department WHERE created_by = $auth_user) OR ->assigned->role->is_under->department->is_under->(organization WHERE created_by = $auth_user) OR ->assigned->role->is_under->department->is_under->(department WHERE created_by = $auth_user)));
                        RETURN $found_user;
                        COMMIT TRANSACTION;
                        "
                    )
                    .bind(("user_id", user_id))
                    .bind(("auth_sub", authenticated_ref.sub.to_owned()))
                    .await.map_err(|e| {
                    tracing::error!("Error fetching user: {}", e);
                    ExtendedError::new("Error fetching user", StatusCode::BAD_REQUEST.as_str())
                        .build()
                })?;

                let user: Option<User> = if is_owner {
                    user_query.take(0).map_err(|e| {
                        tracing::debug!("User deserialization error: {}", e);
                        ExtendedError::new(
                            "Server Error",
                            StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                        )
                        .build()
                    })?
                } else {
                    user_query.take(1).map_err(|e| {
                        tracing::debug!("User deserialization error: {}", e);
                        ExtendedError::new(
                            "Server Error",
                            StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                        )
                        .build()
                    })?
                };

                match user {
                    Some(user) => Ok(user),
                    None => Err(ExtendedError::new(
                        "User not found",
                        StatusCode::NOT_FOUND.as_str(),
                    )
                    .build()),
                }
            }
            None => {
                tracing::error!("Malformed request!");
                return Err(ExtendedError::new(
                    "Malformed request",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build());
            }
        }
    }

    async fn check_auth(&self, ctx: &Context<'_>) -> Result<AuthStatus> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let header_map = ctx.data_opt::<HeaderMap>();

        let auth_status = confirm_authentication(header_map, db).await.map_err(|e| {
            tracing::error!("Error confirming authentication: {:?}", e);
            ExtendedError::new("Unauthorized!", StatusCode::UNAUTHORIZED.as_str()).build()
        })?;

        Ok(auth_status)
    }

    /// Fetches system roles assigned to a given user or under organization created by the user or under department created by the user
    async fn fetch_system_roles(
        &self,
        ctx: &Context<'_>,
        user_id: Option<String>,
    ) -> Result<Vec<SystemRole>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            roles: vec![],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, &authenticated, authorization_constraint).await?;

        if user_id.is_none() {
            if !authorized {
                return Err(
                    ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                );
            }

            let mut fetch_user_roles_query = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $user = type::thing('user', $user_id);
                    IF !$user.exists()
                   	{
                  		THROW 'Invalid Input';
                   	};
                    LET $roles = array::flatten([
                   	(SELECT * FROM role WHERE ->is_under->(organization WHERE created_by = $user)),
                   	(SELECT * FROM role WHERE ->is_under->(department WHERE created_by = $user)),
                   	(SELECT * FROM role WHERE ->is_under->department->is_under->(organization WHERE created_by = $user)),
                   	(SELECT * FROM role WHERE ->is_under->department->is_under->(department WHERE created_by = $user))
                    ]);
                    RETURN $roles;
                    COMMIT TRANSACTION;
                    "
                )
                .bind(("user_id", authenticated_ref.sub.to_owned()))
                .await.map_err(|e| {
                tracing::error!("Error fetching roles: {}", e);
                ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

            let response: Vec<SystemRole> = fetch_user_roles_query.take(0).map_err(|e| {
                tracing::debug!("SystemRole deserialization error: {}", e);
                ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                    .build()
            })?;

            Ok(response)
        } else {
            let user_id = user_id.unwrap();
            if user_id != authenticated.sub && !authorized {
                return Err(
                    ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build(),
                );
            }

            let mut fetch_user_roles_query = db
                .query(
                    "
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);

                IF !$user.exists() {
                    THROW 'Invalid Input';
                };
                LET $roles = (SELECT ->assigned->role.* AS roles FROM ONLY $user)['roles'];
                RETURN $roles;
                COMMIT TRANSACTION;
                ",
                )
                .bind(("user_id", user_id))
                .await
                .map_err(|e| {
                    tracing::error!("Error fetching roles: {}", e);
                    ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str())
                        .build()
                })?;

            let response: Vec<SystemRole> = fetch_user_roles_query.take(0).map_err(|e| {
                tracing::debug!("SystemRole deserialization error: {}", e);
                ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str())
                    .build()
            })?;

            Ok(response)
        }
    }

    /// Fetch all organizations where the user is assigned an admin role and is allowed to create roles/assign roles/create a department
    async fn fetch_organizations(&self, ctx: &Context<'_>) -> Result<Vec<Organization>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            roles: vec![],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, &authenticated, authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut fetch_user_orgs_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);
                IF !$user.exists()
               	{
              		THROW 'Invalid Input';
               	};
                LET $organizations = <set> array::flatten([
                   	(SELECT * FROM organization WHERE created_by = $user),
                   	(SELECT * FROM organization WHERE <-is_under<-(role WHERE (is_admin OR is_super_admin) AND admin_permissions CONTAINSANY [
                  		'CreateDepartment',
                  		'CreateRole',
                  		'AssignRole'
                   	])<-assigned<-(user WHERE id = $user))
                ]);
                RETURN $organizations;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .await
            .map_err(|e| {
                tracing::error!("Error fetching roles: {}", e);
                ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        let response: Vec<Organization> = fetch_user_orgs_query.take(0).map_err(|e| {
            tracing::debug!("SystemRole deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        Ok(response)
    }

    /// Fetch all departments where the user is assigned an admin role and is allowed to create roles/assign roles/create a department
    async fn fetch_departments(&self, ctx: &Context<'_>) -> Result<Vec<Department>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let header_map = ctx.data_opt::<HeaderMap>();

        let authenticated = confirm_authentication(header_map, db).await?;

        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            roles: vec![],
            privilege: Some(AdminPrivilege::Admin),
        };

        let authorized =
            confirm_authorization(db, &authenticated, authorization_constraint).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut fetch_user_departments_query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);
                IF !$user.exists()
               	{
              		THROW 'Invalid Input';
               	};
                LET $departments = array::flatten([
                   	(SELECT * FROM department WHERE created_by = $user),
                   	(SELECT * FROM department WHERE <-is_under<-(role WHERE (is_admin OR is_super_admin) AND admin_permissions CONTAINSANY [
                  		'CreateDepartment',
                  		'CreateRole',
                  		'AssignRole'
                   	])<-assigned<-(user WHERE id = $user)),
                    (SELECT * FROM department WHERE ->is_under->(organization WHERE created_by = $user)),
                    (SELECT * FROM department WHERE ->is_under->(department WHERE created_by = $user))
                ]);
                RETURN $departments;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("user_id", authenticated_ref.sub.to_owned()))
            .await
            .map_err(|e| {
                tracing::error!("Error fetching roles: {}", e);
                ExtendedError::new("Error fetching roles", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        let response: Vec<Department> = fetch_user_departments_query.take(0).map_err(|e| {
            tracing::debug!("SystemRole deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        Ok(response)
    }
}
