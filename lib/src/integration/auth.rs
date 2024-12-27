use std::{collections::HashMap, env, io::Error};

use hyper::HeaderMap;
use crate::utils::{auth::CheckAuthResponse, graphql_api::{perform_mutation_or_query_with_vars, perform_query_without_vars}, models::{AuthStatus, SignInResponse, UserLogins, UserLoginsVar}};

/// Integration method for Authentication Service
pub async fn check_auth_from_acl(headers: HeaderMap) -> Result<AuthStatus, Error> {
    // check auth status from ACL service(graphql query)
    let gql_query = r#"
        query Query {
          checkAuth{
            isAuth
            sub
          }
        }
    "#;

    match headers.get("Authorization") {
        Some(auth_header) => {
            let mut auth_headers = HashMap::new();
            auth_headers.insert("Authorization".to_string(), auth_header.to_str().unwrap().to_string());

            if let Some(cookie_header) =  headers.get("Cookie") {
                auth_headers.insert("Cookie".to_string(), cookie_header.to_str().unwrap().to_string());
            };

            let endpoint = env::var("OAUTH_SERVICE")
            .expect("Missing the OAUTH_SERVICE environment variable.");

            // let client = GQLClient::new_with_headers(endpoint, auth_headers);

            let auth_response = perform_query_without_vars::<CheckAuthResponse>(Some(auth_headers), endpoint.as_str(), gql_query).await;

            println!("auth_response: {:?}", auth_response);

            match auth_response.get_data() {
                Some(auth_response) => {
                    Ok(auth_response.check_auth.to_owned())
                }
                None => {
                    Err(Error::new(std::io::ErrorKind::Other, "ACL server not responding! check_auth_from_acl"))
                }
            }
        }
        None => {
            Err(Error::new(std::io::ErrorKind::Other, "Not Authorized!"))
        }
    }
}

/// Integration method for Authentication Service
pub async fn internal_sign_in() -> Result<String, Error> {
    let gql_query = r#"
        mutation Mutation($rawUserDetails: UserLoginsInput!) {
            signIn(rawUserDetails: $rawUserDetails) {
                token
                url
            }
        }
    "#;

    let endpoint = env::var("OAUTH_SERVICE")
    .expect("Missing the OAUTH_SERVICE environment variable.");
    let username = env::var("INTERNAL_USER")
    .expect("Missing the INTERNAL_USER environment variable.");
    let password = env::var("INTERNAL_USER_PASSWORD")
    .expect("Missing the INTERNAL_USER_PASSWORD environment variable.");

    let logins = UserLogins {
        user_name: Some(username),
        password: Some(password)
    };

    let logins_var = UserLoginsVar {
        raw_user_details: logins
    };

    let auth_response = perform_mutation_or_query_with_vars::<SignInResponse, UserLoginsVar>(None, endpoint.as_str(), gql_query, logins_var).await;

    println!("auth_response: {:?}", auth_response);

    match auth_response.get_data() {
        Some(auth_response) => {
            Ok(auth_response.sign_in.token.clone().unwrap_or("".to_string()))
        }
        None => {
            Err(Error::new(std::io::ErrorKind::Other, "ACL server not responding! check_auth_from_acl"))
        }
    }
}
