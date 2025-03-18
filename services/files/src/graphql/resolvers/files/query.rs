use std::{env, sync::Arc};

use async_graphql::{Context, Object, Result};
use axum::Extension;
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::utils::files::{get_file_id, get_system_filename};

#[derive(Default)]
pub struct FileQuery;

#[Object]
impl FileQuery {
    pub async fn get_file_id(&self, ctx: &Context<'_>, file_name: String) -> Result<String> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let file_id_res = get_file_id(db, file_name).await;

        match file_id_res {
            Ok(file_id) => Ok(file_id),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get_file_name(&self, ctx: &Context<'_>, file_id: String) -> Result<String> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let file_name_res = get_system_filename(db, file_id).await;

        match file_name_res {
            Ok(file_name) => Ok(file_name),
            Err(e) => Err(e.into()),
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
