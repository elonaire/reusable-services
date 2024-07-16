mod middleware;
mod database;
mod graphql;

use core::panic;
use std::{env, sync::Arc, vec};

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::{Extension, Query as AxumQuery},
    http::{HeaderMap, HeaderValue, header::COOKIE as AXUM_COOKIE},
    routing::{get, post},
    Json, Router, serve,
};

use graphql::resolvers::query::Query;
use hyper::{
    header::{ACCEPT, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE},
    Method,
};
use oauth2::{
    basic::BasicTokenType, reqwest::async_http_client, AuthorizationCode, EmptyExtraTokenFields,
    PkceCodeVerifier, StandardTokenResponse,
};
use serde::Deserialize;
use surrealdb::{engine::remote::ws::Client, Result, Surreal};
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;

use crate::middleware::oauth::{initiate_auth_code_grant_flow, OAuthClientName};
use lib::utils::cookie_parser::parse_cookies;

type MySchema = Schema<Query, Mutation, EmptySubscription>;

async fn graphql_handler(
    schema: Extension<MySchema>,
    db: Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut request = req.0;
    request = request.data(db.clone());
    request = request.data(headers.clone());
    schema.execute(request).await.into()
}

#[derive(Debug, Deserialize, Clone)]
struct Params {
    code: Option<String>,
    state: Option<String>,
}

// client agnostic oauth handler
async fn oauth_handler(
    params: AxumQuery<Params>,
    headers: HeaderMap,
) -> Json<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
    // println!("params: {:?}", params.0);
    // get the csrf state from the cookie
    // Extract the csrf_state, oauth_client, pkce_verifier cookies
    // Extract cookies from the headers
    let cookie_header = headers.get(AXUM_COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");

    // Split and parse cookies manually
    let cookie_map: std::collections::HashMap<_, _> = parse_cookies(cookie_header);

    let oauth_client_name = cookie_map.get("oauth_client").expect("OAuth client name cookie not found");
    let pcke_verifier_secret = cookie_map.get("k").expect("PKCE verifier cookie not found");
    let csrf_state = cookie_map.get("j").expect("CSRF state cookie not found");

    if params.0.state.unwrap() != csrf_state.to_owned() {
        panic!("CSRF token mismatch! Aborting request. Might be a hacker 🥷🏻!");
    }

    // We need to get the same client instance that we used to generate the auth url. Hence the cookies.
    let oauth_client =
        initiate_auth_code_grant_flow(OAuthClientName::from_str(oauth_client_name)).await;

    // Generate a PKCE verifier using the secret.
    let pkce_verifier = PkceCodeVerifier::new(pcke_verifier_secret.to_string());
    let auth_code = AuthorizationCode::new(params.0.code.clone().unwrap());

    // Now you can trade it for an access token.
    let token_result = oauth_client
        .exchange_code(auth_code)
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .unwrap();

    Json(token_result)
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = Arc::new(database::connection::create_db_connection().await.unwrap());

    let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS")
                    .expect("Missing the ALLOWED_SERVICES environment variable.");

    let origins: Vec<HeaderValue> = allowed_services_cors.as_str().split(",").into_iter().map(|endpoint| endpoint.parse::<HeaderValue>().unwrap()).collect();

    let app = Router::new()
        .route("/", post(graphql_handler))
        .route("/oauth/callback", get(oauth_handler))
        .layer(Extension(schema))
        .layer(Extension(db))
        .layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE, SET_COOKIE, COOKIE, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_EXPOSE_HEADERS])
                .allow_credentials(true)
                .allow_methods(vec![Method::GET, Method::POST]),
        );

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3003").await.unwrap();
        serve(listener, app)
        .await
        .unwrap();

    Ok(())
}
