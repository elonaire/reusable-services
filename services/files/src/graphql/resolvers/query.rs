use async_graphql::{MergedObject, Object};

use super::files::query::FileQuery;

#[derive(Default)]
pub struct EmptyQuery;

#[Object]
impl EmptyQuery {
    pub async fn health(&self) -> String {
        "Files Service is Online!".to_string()
    }
}

#[derive(MergedObject, Default)]
pub struct Query(EmptyQuery, FileQuery);
