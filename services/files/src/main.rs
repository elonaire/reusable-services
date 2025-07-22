mod database;
mod graphql;
mod grpc;
mod rest;
mod utils;

use std::{
    env,
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::{DefaultBodyLimit, Extension},
    http::{HeaderMap, HeaderValue},
    middleware,
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
    Method,
};

use grpc::server::FilesServiceImplementation;
use lib::{
    integration::grpc::clients::files_service::files_service_server::FilesServiceServer,
    middleware::auth::{grpc::AuthMiddleware, rest::handle_auth_with_refresh},
};
use rest::handlers::{download_file, get_image, upload};
use surrealdb::{engine::remote::ws::Client, Surreal};
use tonic::transport::Server;
use tonic_middleware::MiddlewareLayer;
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;
use tracing_subscriber::fmt::writer::MakeWriterExt;

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

    let operation_name = request.operation_name.clone();

    // Log request info(I just want to deploy Files again)
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
    let connection_pool = database::connection::create_db_connection()
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to the database: {}", e);
            Error::new(
                ErrorKind::ConnectionAborted,
                "Failed to connect to the database",
            )
        })?;
    let db = Arc::new(connection_pool);

    // Bring in some needed env vars
    let deployment_env = env::var("ENVIRONMENT").unwrap_or_else(|_| "prod".to_string()); // default to production because it's the most secure
    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS")
        .expect("Missing the ALLOWED_SERVICES environment variable.");
    let files_http_port =
        env::var("FILES_HTTP_PORT").expect("Missing the FILES_HTTP_PORT environment variable.");
    let files_grpc_port =
        env::var("FILES_GRPC_PORT").expect("Missing the FILES_GRPC_PORT environment variable.");

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
        .into_iter()
        .map(|endpoint| endpoint.parse::<HeaderValue>().unwrap())
        .collect();

    // Persist the server logs to a file on a daily basis using "tracing_subscriber"
    let file_appender = tracing_appender::rolling::daily("./logs", "files.log");
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
        .route("/upload", post(upload))
        .route("/download/{file_name}", get(download_file))
        .route_layer(middleware::from_fn(handle_auth_with_refresh))
        .route("/", post(graphql_handler))
        .route("/view/{file_name}", get(get_image))
        .layer(Extension(schema))
        .layer(Extension(db.clone()))
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

    // Set up the gRPC server
    let files_grpc = FilesServiceImplementation::new(db.clone());
    let grpc_address: SocketAddr = format!("0.0.0.0:{}", files_grpc_port)
        .as_str()
        .parse()
        .unwrap();
    let tonic_auth_middleware = AuthMiddleware::default();

    tokio::spawn(async move {
        // let the thread panic if gRPC server fails to start
        Server::builder()
            .layer(MiddlewareLayer::new(tonic_auth_middleware))
            .add_service(FilesServiceServer::new(files_grpc))
            .serve(grpc_address)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start gRPC server: {}", e);
            })
            .ok();
    });

    match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", files_http_port)).await {
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
