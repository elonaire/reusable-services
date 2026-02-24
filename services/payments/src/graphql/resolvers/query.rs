use async_graphql::{MergedObject, Object};

use crate::graphql::resolvers::payments::query::PaymentQuery;

#[derive(Default)]
pub struct EmptyQuery;

#[Object]
impl EmptyQuery {
    pub async fn health(&self) -> String {
        "Payments Service is Online!".to_string()
    }
}

#[derive(MergedObject, Default)]
pub struct Query(EmptyQuery, PaymentQuery);
