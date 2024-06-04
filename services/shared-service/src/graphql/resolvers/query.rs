use std::sync::Arc;

use async_graphql::{Context, Error, Object};
use axum::Extension;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use crate::graphql::schemas::blog;

pub struct Query;

#[Object]
impl Query {
    pub async fn get_blog_posts(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Vec<blog::BlogPost>> {
        let db = ctx.data::<Extension<Arc<Surreal<SurrealClient>>>>().unwrap();

        let result = db
        .select("blog_post")
        .await
        .map_err(|e| Error::new(e.to_string()))?;

        Ok(result)
    }

    pub async fn get_single_blog_post(
        &self,
        ctx: &Context<'_>,
        link: String,
    ) -> async_graphql::Result<blog::BlogPost> {
        let db = ctx.data::<Extension<Arc<Surreal<SurrealClient>>>>().unwrap();

        let mut result = db
        .query("SELECT * FROM blog_post WHERE link = $link LIMIT 1")
        .bind(("link", link))
        .await
        .map_err(|e| Error::new(e.to_string()))?;

        let post: Option<blog::BlogPost> = result.take(0).unwrap();

        match post {
            Some(post) => Ok(post),
            None => Err(Error::new("Post not found!")),
        }
        // Ok(post)
    }
}