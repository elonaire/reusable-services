use std::collections::HashMap;

use gql_client::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub enum GraphQLResponse<T> {
    Data(T),
    Error(String),
}

impl<T> GraphQLResponse<T> {
    pub fn get_data(&self) -> Option<&T> {
        match self {
            GraphQLResponse::Data(data) => Some(data),
            _ => None,
        }
    }
}

pub async fn perform_query_without_vars<R: for<'de> Deserialize<'de>>(
    headers: Option<HashMap<String, String>>,
    endpoint: &str,
    query: &str,
) -> GraphQLResponse<R> {
    // let endpoint = "http://localhost:3001";

    // create query
    //     let query = r#"
    //        query Query {
    //            getUsers {
    //                id
    //                email
    //                fullName
    //                age
    //            }
    //        }
    //    "#;

    let client = match headers {
        Some(headers) => Client::new_with_headers(endpoint, headers),
        None => Client::new(endpoint),
    };

    let response = client.query::<R>(query).await;

    match response {
        Ok(data) => GraphQLResponse::Data(data.unwrap()),
        Err(err) => GraphQLResponse::Error(format!("{:?}", err)),
    }
}

pub async fn perform_mutation_or_query_with_vars<
    R: for<'de> Deserialize<'de> + Serialize,
    T: for<'de> Deserialize<'de> + Serialize,
>(
    headers: Option<HashMap<String, String>>,
    endpoint: &str,
    query: &str,
    vars: T,
) -> GraphQLResponse<R> {
    // let endpoint = "http://localhost:3001";

    // create query
    // let query = r#"
    //     mutation Mutation($user: UserInput!) {
    //         signUp(user: $user) {
    //             id
    //             email
    //             fullName
    //             age
    //         }
    //     }
    // "#;

    let client = match headers {
        Some(headers) => Client::new_with_headers(endpoint, headers),
        None => Client::new(endpoint),
    };

    let response = client.query_with_vars::<R, T>(query, vars).await;

    match response {
        Ok(data) => GraphQLResponse::Data(data.unwrap()),
        Err(err) => GraphQLResponse::Error(format!("{:?}", err)),
    }
}
