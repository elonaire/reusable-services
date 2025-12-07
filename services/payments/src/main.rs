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
    extract::Extension,
    http::{HeaderMap, HeaderValue},
    routing::post,
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

use grpc::server::PaymentsServiceImplementation;
use lib::{
    integration::grpc::clients::payments_service::payments_service_server::PaymentsServiceServer,
    middleware::auth::grpc::AuthMiddleware, utils::mqtt::MqttClient,
};
use rest::handlers::handle_paystack_webhook;
// use serde::Deserialize;
// use dotenvy::dotenv;
use rumqttc::v5::AsyncClient;
use surrealdb::{engine::remote::ws::Client, Surreal};
use tonic::transport::Server;
use tonic_middleware::MiddlewareLayer;
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;
use tracing_subscriber::fmt::writer::MakeWriterExt;

type MySchema = Schema<Query, Mutation, EmptySubscription>;

pub struct AppState {
    pub mqtt_client: AsyncClient,
}

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

    // Log request info
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
    // Persist the server logs to a file on a daily basis using "tracing_subscriber"
    let file_appender = tracing_appender::rolling::daily("./logs", "payments.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let stdout = std::io::stdout.with_max_level(tracing::Level::DEBUG); // Log to console at DEBUG level

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(stdout.and(non_blocking))
        .init();

    let connection_pool = database::connection::create_db_connection()
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to the database: {}", e);
            Error::new(
                ErrorKind::ConnectionRefused,
                "Failed to connect to the database",
            )
        })?;
    let db = Arc::new(connection_pool);

    // Bring in some needed env vars
    let deployment_env = env::var("ENVIRONMENT").unwrap_or_else(|_| "prod".to_string()); // default to production because it's the most secure
    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS")
        .expect("Missing the ALLOWED_SERVICES environment variable.");
    let payments_http_port = env::var("PAYMENTS_HTTP_PORT")
        .expect("Missing the PAYMENTS_HTTP_PORT environment variable.");
    let payments_grpc_port = env::var("PAYMENTS_GRPC_PORT")
        .expect("Missing the PAYMENTS_GRPC_PORT environment variable.");
    let mqtt_host = env::var("MQTT_HOST").expect("Missing the MQTT_HOST environment variable.");
    let mqtt_port = env::var("MQTT_PORT").expect("Missing the MQTT_PORT environment variable.");

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

    let (client, mut eventloop) =
        MqttClient::new("payments-service", &mqtt_host, mqtt_port.parse().unwrap()).await?;

    let shared_state = Arc::new(AppState {
        mqtt_client: client,
    });

    let app = Router::new()
        .route("/", post(graphql_handler))
        .route("/paystack/webhook", post(handle_paystack_webhook))
        .layer(Extension(shared_state))
        .layer(Extension(schema))
        .layer(Extension(db.clone()))
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
    let payments_grpc = PaymentsServiceImplementation::new(db.clone());
    let grpc_address: SocketAddr = format!("0.0.0.0:{}", payments_grpc_port)
        .as_str()
        .parse()
        .expect("The gRPC address must be set");
    let tonic_auth_middleware = AuthMiddleware::default();

    tokio::spawn(async move {
        // let the thread panic if gRPC server fails to start
        Server::builder()
            .layer(MiddlewareLayer::new(tonic_auth_middleware))
            .add_service(PaymentsServiceServer::new(payments_grpc))
            .serve(grpc_address)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start gRPC server: {}", e);
            })
            .ok();
    });

    tokio::spawn(async move { while let Ok(_event) = eventloop.poll().await {} });

    match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", payments_http_port)).await {
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
