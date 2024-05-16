use std::{collections::HashMap, env, io::Error};

use async_graphql::Context;
// use axum::{http::HeaderValue, Extension};
use gql_client::Client as GQLClient;
use hyper::HeaderMap;
use lib::utils::auth::DecodeTokenResponse;
// use lib::utils::custom_error::ExtendedError;
// use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

pub async fn check_auth_from_acl(ctx: &Context<'_>) -> Result<Option<DecodeTokenResponse>, Error> {
    match ctx.data_opt::<HeaderMap>() {
        Some(headers) => {
            // check auth status from ACL service(graphql query)
            let gql_query = r#"
                mutation Mutation {
                    decodeToken
                }
            "#;

            match headers.get("Authorization") {
                Some(auth_header) => {
                    println!("auth_header: {:?}", auth_header.to_str().unwrap());
                    // let mut auth_status = String::new();
                    // println!("auth_status: {:?}", auth_status);
                    let mut auth_headers = HashMap::new();
                    auth_headers.insert("Authorization", auth_header.to_str().unwrap());

                    let endpoint = env::var("OAUTH_SERVICE")
                    .expect("Missing the OAUTH_SERVICE environment variable.");

                    let client = GQLClient::new_with_headers(endpoint, auth_headers);

                    let auth_response = client.query::<DecodeTokenResponse>(gql_query).await;

                    println!("auth_response: {:?}", auth_response);
                    
                    match auth_response {
                        Ok(auth_response) => {
                            Ok(auth_response)
                        }
                        Err(_) => {
                            Err(Error::new(std::io::ErrorKind::Other, "ACL server not responding!"))
                        }
                    }
                }
                None => {
                    Err(Error::new(std::io::ErrorKind::Other, "Not Authorized!"))
                }
            }
        }
        None => Err(Error::new(std::io::ErrorKind::Other, "Not Authorized!")),
    }
}