use async_graphql::{MergedObject, Object};

#[derive(Default)]
pub struct EmptyQuery;

#[Object]
impl EmptyQuery {
    pub async fn health(&self) -> String {
        "Email Service is Online!".to_string()
    }
}

#[derive(MergedObject, Default)]
pub struct Query(EmptyQuery);
