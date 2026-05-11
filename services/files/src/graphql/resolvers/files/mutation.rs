use std::sync::Arc;

use async_graphql::{Context, Object, Result};
use axum::Extension;
use hyper::{HeaderMap, StatusCode};
use lib::{
    integration::foreign_key::add_foreign_key_if_not_exists,
    middleware::auth::false_graphql::confirm_authentication,
    utils::{
        api_responses::synthesize_graphql_response,
        custom_error::ExtendedError,
        grpc::confirm_authorization,
        models::{AuthorizationConstraint, ForeignKey, UserId},
    },
};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::graphql::schemas::{
    general::{Bucket, BucketInput, Key, KeyInput, KeyInputMetadata},
    shared::GraphQLApiResponse,
};

#[derive(Default)]
pub struct FileMutation;

#[Object]
impl FileMutation {
    pub async fn health(&self, your_name: String) -> String {
        format!("Hi {}, Files Service is Online!", your_name)
    }

    /// Create a new bucket
    async fn create_bucket(
        &self,
        ctx: &Context<'_>,
        mut bucket_input: BucketInput,
    ) -> Result<GraphQLApiResponse<Bucket>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let headers = ctx.data::<HeaderMap>().map_err(|e| {
            tracing::error!("Error HeaderMap: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(ctx).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:bucket".into()],
        };

        let authenticated_ref = &authenticated;
        let authorization_constraint_ref = &authorization_constraint;

        let authorized =
            confirm_authorization(authenticated_ref, authorization_constraint_ref, headers).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let user_fk = ForeignKey {
            table: "user_id".to_string(),
            column: "user_id".to_string(),
            foreign_key: authenticated_ref.sub.to_owned(),
        };

        let Some(added_id) =
            add_foreign_key_if_not_exists::<Extension<Arc<Surreal<Client>>>, UserId>(db, user_fk)
                .await
        else {
            return Err(ExtendedError::new(
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
            )
            .build());
        };

        bucket_input.owner = Some(added_id.id);

        let mut query = db
            .query(
                "
                BEGIN TRANSACTION;

                LET $created_bucket = (
                    CREATE ONLY bucket CONTENT $bucket_input RETURN AFTER
                );

                LET $bucket = (
                    SELECT *
                    FROM ONLY $created_bucket
                    FETCH owner
                );

                RETURN $bucket;

                COMMIT TRANSACTION;
                ",
            )
            .bind(("bucket_input", bucket_input))
            .await
            .map_err(|e| {
                tracing::error!("Error creating bucket: {}", e);
                ExtendedError::new("Failed to create bucket", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let response: Option<Bucket> = query.take(3).map_err(|e| {
            tracing::error!("Failed to deserialize bucket: {}", e);
            ExtendedError::new("Failed to create bucket", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        match response {
            Some(bucket) => {
                let api_response =
                    synthesize_graphql_response(ctx, &bucket, Some(authenticated_ref)).ok_or_else(
                        || {
                            tracing::error!("Failed to synthesize response!");
                            ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str())
                                .build()
                        },
                    )?;

                Ok(api_response.into())
            }
            None => Err(ExtendedError::new(
                "Failed to create bucket",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    /// Create a new key
    async fn create_key(
        &self,
        ctx: &Context<'_>,
        mut key_input: KeyInput,
        key_input_metadata: KeyInputMetadata,
    ) -> Result<GraphQLApiResponse<Key>> {
        if key_input_metadata.bucket_id.is_none() && key_input_metadata.key_id.is_none() {
            return Err(ExtendedError::new(
                "Bucket ID or Key ID must be provided",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build());
        }

        if key_input_metadata.bucket_id.is_some() && key_input_metadata.key_id.is_some() {
            return Err(ExtendedError::new(
                "Provide either a Bucket ID or a Key ID, not both",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build());
        }

        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let headers = ctx.data::<HeaderMap>().map_err(|e| {
            tracing::error!("Error HeaderMap: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(ctx).await?;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:key".into()],
        };

        let authenticated_ref = &authenticated;
        let authorization_constraint_ref = &authorization_constraint;

        let authorized =
            confirm_authorization(authenticated_ref, authorization_constraint_ref, headers).await?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let user_fk = ForeignKey {
            table: "user_id".to_string(),
            column: "user_id".to_string(),
            foreign_key: authenticated_ref.sub.to_owned(),
        };

        let Some(added_id) =
            add_foreign_key_if_not_exists::<Extension<Arc<Surreal<Client>>>, UserId>(db, user_fk)
                .await
        else {
            return Err(ExtendedError::new(
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
            )
            .build());
        };

        key_input.owner = Some(added_id.id);

        let mut query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $created_key = (CREATE ONLY key CONTENT $key_input RETURN AFTER);

                IF $key_input_metadata.key_id IS NOT NONE {
                    LET $existing_key = type::record('key', $key_input_metadata.key_id);

                    LET $result = (SELECT <-belongs_to<-(key WHERE name = $created_key.name) AS existing_key FROM ONLY key WHERE id = $existing_key LIMIT 1)['existing_key'];

                    LET $found_duplicate = array::len($result) > 0;

                    IF $found_duplicate {
                        THROW 'Forbidden! Duplicate keys not allowed!';
                    };

                    RELATE $created_key -> belongs_to -> $existing_key;
                };

                IF $key_input_metadata.bucket_id IS NOT NONE {
                    LET $existing_bucket = type::record('bucket', $key_input_metadata.bucket_id);

                    LET $result = (SELECT <-belongs_to<-(key WHERE name = $created_key.name) AS existing_key FROM ONLY bucket WHERE id = $existing_bucket LIMIT 1)['existing_key'];

                    LET $found_duplicate = array::len($result) > 0;

                    IF $found_duplicate {
                        THROW 'Forbidden! Duplicate keys not allowed!';
                    };

                    RELATE $created_key -> belongs_to -> $existing_bucket;
                };

                LET $key = (SELECT * FROM ONLY $created_key FETCH owner);
                RETURN $key;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("key_input", key_input))
            .bind(("key_input_metadata", key_input_metadata))
            .await
            .map_err(|e| {
                tracing::error!("Error creating key: {}", e);
                ExtendedError::new("Failed to create key", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        let response: Option<Key> = query.take(5).map_err(|e| {
            tracing::error!("Failed to create key: {}", e);
            ExtendedError::new("Failed to create key", StatusCode::BAD_REQUEST.as_str()).build()
        })?;

        match response {
            Some(key) => {
                let api_response = synthesize_graphql_response(ctx, &key, Some(authenticated_ref))
                    .ok_or_else(|| {
                        tracing::error!("Failed to synthesize response!");
                        ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
                    })?;

                Ok(api_response.into())
            }
            None => Err(ExtendedError::new(
                "Failed to create key",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }
}
