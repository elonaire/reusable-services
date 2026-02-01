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
    vec,
};

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue},
    routing::{get, post},
    serve, Router,
};

use axum_cookie::CookieLayer;
use graphql::resolvers::query::Query;
use grpc::server::AclServiceImplementation;
use hyper::{
    header::{
        ACCEPT, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE,
    },
    Method, StatusCode,
};
use rest::handlers::{exchange_code_for_token, oauth_callback_handler, verify_email_handler};
use rumqttc::v5::AsyncClient;
use surrealdb::{engine::remote::ws::Client, Surreal};
use tonic::transport::Server;
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;
use tracing_subscriber::fmt::writer::MakeWriterExt;

use lib::{
    integration::grpc::clients::acl_service::acl_server::AclServer, utils::mqtt::MqttClient,
};
use uuid::Uuid;

type MySchema = Schema<Query, Mutation, EmptySubscription>;

pub struct AppState {
    pub mqtt_client: AsyncClient,
}

async fn graphql_handler(
    schema: Extension<MySchema>,
    db: Extension<Arc<Surreal<Client>>>,
    mqtt_client: Extension<Arc<AppState>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut request = req.0;

    let db = db.clone();
    let mut headers = headers.clone();
    let mqtt_client = mqtt_client.clone();
    let request_id = Uuid::new_v4();
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).unwrap_or(HeaderValue::from_static("")),
    );

    request = request.data(db);
    request = request.data(headers);
    request = request.data(mqtt_client);
    tracing::debug!("Request data set!");
    let operation_name = request.operation_name.clone();

    // Log request info(I just want to deploy ACL again)
    tracing::info!("Executing GraphQL request: {:?}", &operation_name);
    let start = std::time::Instant::now();

    // Execute the GraphQL request
    let response = schema.execute(request).await;

    let duration = start.elapsed();
    tracing::info!("{:?} request processed in {:?}", operation_name, duration);

    // Debug the response
    if response.errors.len() > 0 {
        tracing::error!("GraphQL Error: {:?}", response.errors);
    } else {
        tracing::info!("GraphQL request completed without errors");
    }

    // Convert GraphQL response into the Axum response type
    response.into()
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Persist the server logs to a file on a daily basis using "tracing_subscriber"
    let file_appender = tracing_appender::rolling::daily("./logs", "acl.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let stdout = std::io::stdout
        .with_filter(|meta| {
            meta.target() != "h2::codec::framed_write"
                && meta.target() != "h2::codec::framed_read"
                && meta.target() != "rumqttc::v5::state"
        })
        .with_max_level(tracing::Level::DEBUG); // Log to console at DEBUG level

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(stdout.and(non_blocking))
        .init();

    let connection_pool = database::connection::create_db_connection()
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to the database: {}", e);
            Error::new(ErrorKind::ConnectionAborted, format!("{}", e))
        })?;
    let db = Arc::new(connection_pool);

    // Bring in some needed env vars
    let deployment_env = env::var("ENVIRONMENT").unwrap_or_else(|_| "prod".to_string()); // default to production because it's the most secure
    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "ALLOWED_SERVICES_CORS not set")
    })?;
    let acl_http_port = env::var("ACL_HTTP_PORT").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "ACL_HTTP_PORT not set")
    })?;
    let acl_grpc_port = env::var("ACL_GRPC_PORT").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "ACL_GRPC_PORT not set")
    })?;
    let mqtt_host = env::var("MQTT_HOST").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "MQTT_HOST not set")
    })?;
    let mqtt_port = env::var("MQTT_PORT").map_err(|e| {
        tracing::error!("Config Error: {}", e);
        Error::new(ErrorKind::Other, "MQTT_PORT not set")
    })?;

    // Initialize the schema builder
    let mut schema_builder = Schema::build(Query, Mutation, EmptySubscription);

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
        MqttClient::new("acl-service", &mqtt_host, mqtt_port.parse().unwrap()).await?;

    tokio::spawn(async move { while let Ok(_event) = eventloop.poll().await {} });

    let shared_state = Arc::new(AppState {
        mqtt_client: client,
    });

    let app = Router::new()
        .route("/", post(graphql_handler))
        .route("/oauth/callback", get(oauth_callback_handler))
        .route("/social-sign-in", post(exchange_code_for_token))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/ready", get(|| async { StatusCode::OK }))
        .route("/verify-email", get(verify_email_handler))
        .layer(Extension(shared_state))
        .layer(CookieLayer::strict())
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
    let acl_grpc = AclServiceImplementation::new(db.clone());
    let grpc_address: SocketAddr = format!("0.0.0.0:{}", acl_grpc_port)
        .as_str()
        .parse()
        .map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(ErrorKind::Other, "gRPC address not set")
        })?;

    tokio::spawn(async move {
        // let the thread panic if gRPC server fails to start
        Server::builder()
            .add_service(AclServer::new(acl_grpc))
            .serve(grpc_address)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start gRPC server: {}", e);
            })
            .ok();
    });

    match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", acl_http_port)).await {
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
