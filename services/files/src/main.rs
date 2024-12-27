mod database;
mod graphql;
mod rest;

use std::{env, sync::Arc};

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::{DefaultBodyLimit, Extension},
    http::{HeaderMap, HeaderValue},
    routing::{get, post},
    serve, Router,
};

use dotenvy::dotenv;
use graphql::resolvers::query::Query;
use hyper::{
    header::{
        ACCEPT, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE,
    },
    Method,
};

use rest::handlers::{download_file, get_image, upload};
// use serde::Deserialize;
use surrealdb::{engine::remote::ws::Client, Result, Surreal};
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;

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

    tracing::info!("Executing GraphQL request: {:?}", request);

    // Execute the GraphQL request
    let response = schema.execute(request).await;

    // Log the response
    tracing::debug!("GraphQL response: {:?}", response);

    // Convert GraphQL response into the Axum response type
    response.into()
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let db = Arc::new(database::connection::create_db_connection().await.unwrap());

    let schema = Schema::build(Query::default(), Mutation::default(), EmptySubscription).finish();

    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS")
        .expect("Missing the ALLOWED_SERVICES environment variable.");

    let origins: Vec<HeaderValue> = allowed_services_cors
        .as_str()
        .split(",")
        .into_iter()
        .map(|endpoint| endpoint.parse::<HeaderValue>().unwrap())
        .collect();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let app = Router::new()
        .route("/", post(graphql_handler))
        .route("/upload", post(upload))
        .route("/view/:file_name", get(get_image))
        .route("/download/:file_name", get(download_file))
        .layer(Extension(schema))
        .layer(Extension(db))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_headers([
                    AUTHORIZATION,
                    ACCEPT,
                    CONTENT_TYPE,
                    SET_COOKIE,
                    COOKIE,
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    ACCESS_CONTROL_ALLOW_HEADERS,
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    ACCESS_CONTROL_ALLOW_METHODS,
                    ACCESS_CONTROL_EXPOSE_HEADERS,
                ])
                .allow_credentials(true)
                .allow_methods(vec![Method::GET, Method::POST]),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    serve(listener, app).await.unwrap();

    Ok(())
}
