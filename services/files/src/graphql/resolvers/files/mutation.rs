use async_graphql::Object;

#[derive(Default)]
pub struct FileMutation;

#[Object]
impl FileMutation {
    pub async fn health(&self, your_name: String) -> String {
        format!("Hi {}, Files Service is Online!", your_name)
    }
}
