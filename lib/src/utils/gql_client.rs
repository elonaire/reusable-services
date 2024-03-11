use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub enum GraphQLClientResponse<T> {
    Data(T),
    Error(String),
}

impl<T> GraphQLClientResponse<T> {
    pub fn get_data(&self) -> Option<&T> {
        match self {
            GraphQLClientResponse::Data(data) => Some(data),
            _ => None,
        }
    }
}
