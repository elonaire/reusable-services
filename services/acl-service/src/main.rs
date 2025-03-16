mod database;
mod graphql;
mod grpc;
mod utils;

use core::panic;
use std::{env, net::SocketAddr, sync::Arc, vec};

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::{Extension, Query as AxumQuery},
    http::{header::COOKIE as AXUM_COOKIE, HeaderMap, HeaderValue},
    routing::{get, post},
    serve, Json, Router,
};

use graphql::resolvers::query::Query;
use grpc::server::{acl_service::acl_server::AclServer, AclServiceImplementation};
use hyper::{
    header::{
        ACCEPT, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE,
    },
    Method,
};
use oauth2::{
    basic::BasicTokenType, AuthorizationCode, EmptyExtraTokenFields, PkceCodeVerifier,
    StandardTokenResponse,
};
use serde::Deserialize;
use surrealdb::{engine::remote::ws::Client, Result, Surreal};
use tonic::transport::Server;
use tower_http::cors::CorsLayer;

use graphql::resolvers::mutation::Mutation;
use tracing_subscriber::fmt::writer::MakeWriterExt;

use crate::utils::auth::{initiate_auth_code_grant_flow, OAuthClientName};
use lib::utils::cookie_parser::parse_cookies;

type MySchema = Schema<Query, Mutation, EmptySubscription>;

async fn graphql_handler(
    schema: Extension<MySchema>,
    db: Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut request = req.0;

    // let mut data = async_graphql::Data::default();
    // data.insert(db.clone());
    // data.insert(headers.clone());
    // request = request.data(data);
    let db = db.clone();
    let headers = headers.clone();

    request = request.data(db);
    request = request.data(headers);
    tracing::debug!("Request data set!");
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
    let cookie_header = headers
        .get(AXUM_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Split and parse cookies manually
    let cookie_map: std::collections::HashMap<_, _> = parse_cookies(cookie_header);

    let oauth_client_name = cookie_map
        .get("oauth_client")
        .expect("OAuth client name cookie not found");
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

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Now you can trade it for an access token.
    let token_result = oauth_client
        .exchange_code(auth_code)
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .unwrap();

    Json(token_result)
}

#[tokio::main]
async fn main() -> Result<()> {
    // let the thread panic if database connection fails
    let db = Arc::new(database::connection::create_db_connection().await.unwrap());

    let schema = Schema::build(Query, Mutation, EmptySubscription)
        .limit_depth(5)
        .finish();

    // Bring in some needed env vars
    let allowed_services_cors = env::var("ALLOWED_SERVICES_CORS")
        .expect("Missing the ALLOWED_SERVICES environment variable.");
    let acl_http_port =
        env::var("ACL_HTTP_PORT").expect("Missing the ACL_HTTP_PORT environment variable.");
    let acl_grpc_port =
        env::var("ACL_GRPC_PORT").expect("Missing the ACL_GRPC_PORT environment variable.");

    let origins: Vec<HeaderValue> = allowed_services_cors
        .as_str()
        .split(",")
        .into_iter()
        .map(|endpoint| endpoint.parse::<HeaderValue>().unwrap())
        .collect();

    // Persist the server logs to a file on a daily basis using "tracing_subscriber"
    let file_appender = tracing_appender::rolling::daily("./logs", "acl.log");
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
        .route("/oauth/callback", get(oauth_handler))
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
    let grpc_address: SocketAddr = format!("[::1]:{}", acl_grpc_port).as_str().parse().unwrap();

    tokio::spawn(async move {
        // let the thread panic if gRPC server fails to start
        Server::builder()
            .add_service(AclServer::new(acl_grpc))
            .serve(grpc_address)
            .await
            .unwrap();
    });

    // Set up the http server and start it; let the thread panic if http server fails to start
    let http_listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", acl_http_port))
        .await
        .unwrap();
    let _http_server = serve(http_listener, app).await.unwrap();

    Ok(())
}
