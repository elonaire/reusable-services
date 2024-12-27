use async_graphql::{MergedObject, Object};

use super::email::mutation::EmailMutation;

#[derive(Default)]
pub struct EmptyMutation;

#[Object]
impl EmptyMutation {
    pub async fn health(&self, your_name: String) -> String {
        format!("Hi {}, Email Service is Online!", your_name)
    }
}

#[derive(MergedObject, Default)]
pub struct Mutation(EmptyMutation, EmailMutation);
