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
    pub async fn get_file_id(&self, ctx: &Context<'_>, file_name: String) -> Result<String> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let mut file_query = db
            .query(
                "
            BEGIN TRANSACTION;

            LET $file = (SELECT * FROM ONLY file WHERE system_filename=$file_name LIMIT 1);

            RETURN $file;
            COMMIT TRANSACTION;
            ",
            )
            .bind(("file_name", file_name))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        let response: Option<UploadedFile> = file_query.take(0)?;

        match response {
            Some(file) => Ok(file.id.as_ref().map(|t| &t.id).expect("id").to_raw()),
            None => Err(ExtendedError::new("Invalid parameters!", Some(400.to_string())).build()),
        }
    }

    pub async fn get_file_name(&self, ctx: &Context<'_>, file_id: String) -> Result<String> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let mut file_query = db
            .query(
                "
            BEGIN TRANSACTION;
            LET $file_thing = type::thing($file_id);

            LET $file = (SELECT * FROM ONLY $file_thing LIMIT 1);

            RETURN $file;
            COMMIT TRANSACTION;
            ",
            )
            .bind(("file_id", format!("file:{}", file_id)))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        let response: Option<UploadedFile> = file_query.take(0)?;

        match response {
            Some(file) => Ok(file.system_filename),
            None => Err(ExtendedError::new("Invalid parameters!", Some(400.to_string())).build()),
        }
    }

    pub async fn serve_md_files(&self, _ctx: &Context<'_>, file_name: String) -> Result<String> {
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
