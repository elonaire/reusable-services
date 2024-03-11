use async_graphql::Object;

pub struct Query;

#[Object]
impl Query {
    async fn user(&self) -> bool {
        true
    }
}