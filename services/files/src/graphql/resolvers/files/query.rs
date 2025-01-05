use std::{env, sync::Arc};

use async_graphql::{Context, Error, Object, Result};
use axum::Extension;
use lib::utils::custom_error::ExtendedError;
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::graphql::schemas::general::UploadedFile;

#[derive(Default)]
pub struct FileQuery;

#[Object]
impl FileQuery {
    pub async fn get_product_artifact(
        &self,
        ctx: &Context<'_>,
        external_product_id: String,
        external_license_id: String,
    ) -> Result<String> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let mut product_artifact_query = db
        .query(
            "
            BEGIN TRANSACTION;
            LET $internal_product = (SELECT VALUE id FROM ONLY product_id WHERE product_id=$product_id LIMIT 1);
            LET $internal_license = (SELECT VALUE id FROM ONLY license_id WHERE license_id=$license_id LIMIT 1);

            LET $file = (SELECT * FROM ONLY file WHERE <-(product_license_artifact WHERE license=$internal_license AND in=$internal_product) LIMIT 1);

            RETURN $file;
            COMMIT TRANSACTION;
            "
        )
        .bind(("product_id", external_product_id))
        .bind(("license_id", external_license_id))
        .await
        .map_err(|e| Error::new(e.to_string()))?;

        let response: Option<UploadedFile> = product_artifact_query.take(0)?;

        match response {
            Some(file) => Ok(file.system_filename),
            None => Err(ExtendedError::new("Invalid parameters!", Some(400.to_string())).build()),
        }
    }

    pub async fn serve_md_files(&self, _ctx: &Context<'_>, file_name: String) -> Result<String> {
        // let files_service = env::var("FILES_SERVICE_PROD")
        //     .expect("Missing the FILES_SERVICE_PROD environment variable.");

        let files_service =
            env::var("FILES_SERVICE").expect("Missing the FILES_SERVICE environment variable.");

        let file_url = format!("{}/view/{}", files_service, file_name);

        match reqwest::get(file_url).await {
            Ok(res) => match res.text().await {
                Ok(data) => {
                    let raw_html =
                        markdown::to_html_with_options(data.as_str(), &markdown::Options::gfm());

                    Ok(raw_html.unwrap())
                }
                Err(_e) => Ok("".into()),
            },
            Err(_e) => Ok("".into()),
        }
    }
}
