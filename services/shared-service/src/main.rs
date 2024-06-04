mod database;
mod graphql;
mod middleware;

use std::sync::Arc;

use async_graphql::{http::{Credentials, GraphiQLSource}, EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{Extension, response::{IntoResponse, Html}, Router, routing::get, http::HeaderValue};
use graphql::resolvers::{mutation::Mutation, query::Query};
use hyper::{header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE}, HeaderMap, Method, Server};
use surrealdb::{Surreal, engine::remote::ws::Client, Result};
use tower_http::cors::CorsLayer;

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

async fn graphiql() -> impl IntoResponse {
    Html(GraphiQLSource::build().endpoint("/").title("Shared Service").credentials(Credentials::Include).finish())
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = Arc::new(database::connection::create_db_connection().await.unwrap());

    let schema = Schema::build(Query, Mutation, EmptySubscription).finish();

    println!("GraphiQL IDE: http://localhost:3002");

    let origins = [
        "http://localhost:8080".parse::<HeaderValue>().unwrap(),
        "http://localhost:3002".parse::<HeaderValue>().unwrap(),
        "http://localhost:3003".parse::<HeaderValue>().unwrap(),
    ];

    let app = Router::new()
        .route("/", get(graphiql).post(graphql_handler))
        .layer(Extension(schema))
        .layer(Extension(db))
        .layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
                .allow_credentials(true)
                .allow_methods(vec![Method::GET, Method::POST]),
        );

    Server::bind(&"0.0.0.0:3002".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
