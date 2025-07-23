mod graphql;
mod grpc;
mod rest;
mod utils;

// use dotenvy::dotenv;
use lib::{
    integration::grpc::clients::email_service::email_service_server::EmailServiceServer,
    middleware::auth::grpc::AuthMiddleware,
};
use std::{
    env,
    io::{Error, ErrorKind},
    net::SocketAddr,
};
use tonic::transport::Server;
use tonic_middleware::MiddlewareLayer;
use tracing_subscriber::fmt::writer::MakeWriterExt;

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue},
    routing::{get, post},
    serve, Router,
};

use graphql::resolvers::query::Query;
use hyper::{
    header::{
        ACCEPT, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE,
    },
    Method, StatusCode,
};

// use serde::Deserialize;
// use surrealdb::{engine::remote::ws::Client, Result, Surreal};
use grpc::server::EmailServiceImplementation;
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;

type MySchema = Schema<Query, Mutation, EmptySubscription>;

async fn graphql_handler(
    schema: Extension<MySchema>,
    // db: Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut request = req.0;
    // request = request.data(db.clone());
    request = request.data(headers.clone());
    let operation_name = request.operation_name.clone();

    // Log request info(I just want to deploy Email again)
    tracing::info!("Executing GraphQL request: {:?}", &operation_name);
    let start = std::time::Instant::now();

    // Execute the GraphQL request
    let response = schema.execute(request).await;

    let duration = start.elapsed();
    tracing::info!("{:?} request processed in {:?}", operation_name, duration);

    // Debug the response
    if response.errors.len() > 0 {
        tracing::debug!("GraphQL Error: {:?}", response.errors);
    } else {
        tracing::info!("GraphQL request completed without errors");
    }

    // Convert GraphQL response into the Axum response type
    response.into()
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // dotenv().ok();
    // let db = Arc::new(database::connection::create_db_connection().await.unwrap());

    // Bring in some needed env vars
    let deployment_env = env::var("ENVIRONMENT").unwrap_or_else(|_| "prod".to_string()); // default to production because it's the most secure
    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS")
        .expect("Missing the ALLOWED_SERVICES environment variable.");
    let email_http_port =
        env::var("EMAIL_HTTP_PORT").expect("Missing the EMAIL_HTTP_PORT environment variable.");
    let email_grpc_port =
        env::var("EMAIL_GRPC_PORT").expect("Missing the EMAIL_GRPC_PORT environment variable.");

    // Initialize the schema builder
    let mut schema_builder =
        Schema::build(Query::default(), Mutation::default(), EmptySubscription);

    // Disable introspection & limit query depth in production
    schema_builder = match deployment_env.as_str() {
        "prod" => schema_builder.disable_introspection().limit_depth(5),
        _ => schema_builder,
    };

    let schema = schema_builder.finish();

    let origins: Vec<HeaderValue> = allowed_services_cors
        .as_str()
        .split(",")
        .filter_map(|endpoint| endpoint.trim().parse::<HeaderValue>().ok())
        .collect();

    // Persist the server logs to a file on a daily basis using "tracing_subscriber"
    let file_appender = tracing_appender::rolling::daily("./logs", "email.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let stdout = std::io::stdout
        .with_filter(|meta| {
            meta.target() != "h2::codec::framed_write" && meta.target() != "h2::codec::framed_read"
        })
        .with_max_level(tracing::Level::DEBUG); // Log to console at DEBUG level

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(stdout.and(non_blocking))
        .init();

    let app = Router::new()
        .route("/", post(graphql_handler))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/ready", get(|| async { StatusCode::OK }))
        .layer(Extension(schema))
        // .layer(Extension(db))
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

    // Set up the gRPC server
    let email_grpc = EmailServiceImplementation::default();
    let grpc_address: SocketAddr = format!("0.0.0.0:{}", email_grpc_port)
        .as_str()
        .parse()
        .expect("The gRPC address must be set");
    let tonic_auth_middleware = AuthMiddleware::default();

    tokio::spawn(async move {
        // let the thread panic if gRPC server fails to start
        Server::builder()
            .layer(MiddlewareLayer::new(tonic_auth_middleware))
            .add_service(EmailServiceServer::new(email_grpc))
            .serve(grpc_address)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start gRPC server: {}", e);
            })
            .ok();
    });

    match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", email_http_port)).await {
        Ok(http_listener) => {
            let _http_server = serve(http_listener, app)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create HTTP server: {}", e);
                })
                .ok();
        }
        Err(e) => {
            tracing::error!("Failed to create TCP listener: {}", e);
            return Err(Error::new(
                ErrorKind::ConnectionAborted,
                "Failed to create TCP listener",
            ));
        }
    };

    Ok(())
}
