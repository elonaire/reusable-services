use std::sync::Arc;

use crate::graphql::schemas::general::UploadedFile;
use async_graphql::{Context, Error, Object, Result};
use axum::{http::HeaderMap, Extension};
use lib::{
    integration::{auth::check_auth_from_acl, foreign_key::add_foreign_key_if_not_exists},
    utils::{
        custom_error::ExtendedError,
        models::{ForeignKey, User},
    },
};
use surrealdb::{engine::remote::ws::Client, Surreal};

#[derive(Default)]
pub struct FileMutation;

#[Object]
impl FileMutation {
    pub async fn buy_product_artifact(
        &self,
        ctx: &Context<'_>,
        file_name: String,
    ) -> Result<String> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        if let Some(headers) = ctx.data_opt::<HeaderMap>() {
            let auth_status = check_auth_from_acl(headers.clone()).await?;
            let bought_artifact =
                buy_product_artifact_util(&ctx, &db, auth_status.sub.clone(), file_name).await?;

            Ok(bought_artifact.system_filename)
        } else {
            Err(ExtendedError::new("Invalid Request!", Some(400.to_string())).build())
        }
    }

    pub async fn buy_product_artifact_webhook(
        &self,
        ctx: &Context<'_>,
        file_name: String,
        ext_user_id: String,
    ) -> Result<String> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        if let Some(headers) = ctx.data_opt::<HeaderMap>() {
            let _auth_status = check_auth_from_acl(headers.clone()).await?;
            let bought_artifact =
                buy_product_artifact_util(&ctx, &db, ext_user_id.clone(), file_name).await?;

            Ok(bought_artifact.system_filename)
        } else {
            Err(ExtendedError::new("Invalid Request!", Some(400.to_string())).build())
        }
    }
}

async fn buy_product_artifact_util(
    ctx: &Context<'_>,
    db: &Extension<Arc<Surreal<Client>>>,
    ext_user_id: String,
    file_name: String,
) -> Result<UploadedFile> {
    let user_fk_body = ForeignKey {
        table: "user_id".into(),
        column: "user_id".into(),
        foreign_key: ext_user_id,
    };

    let internal_user = add_foreign_key_if_not_exists::<User>(ctx, user_fk_body).await;

    let mut file_query = db
        .query(
            "
        BEGIN TRANSACTION;
        LET $internal_user = type::thing($user_id);
        LET $file = (SELECT VALUE id FROM ONLY file WHERE system_filename=$file_name LIMIT 1);

        RELATE $internal_user -> bought_file -> $file;
        LET $actual_file = (SELECT * FROM ONLY $file);
        RETURN $actual_file;
        COMMIT TRANSACTION;
        ",
        )
        .bind(("file_name", file_name))
        .bind((
            "user_id",
            format!(
                "user_id:{}",
                internal_user
                    .unwrap()
                    .id
                    .as_ref()
                    .map(|t| &t.id)
                    .expect("id")
                    .to_raw()
            ),
        ))
        .await
        .map_err(|e| Error::new(e.to_string()))?;

    let file_query_response: Option<UploadedFile> = file_query.take(0)?;

    match file_query_response {
        Some(file) => Ok(file),
        None => {
            Err(ExtendedError::new("Failed to purchase artifact!", Some(500.to_string())).build())
        }
    }
}
