use async_graphql::{Context, OutputType};
use hyper::HeaderMap;
use serde::Serialize;

use crate::utils::models::{ApiResponse, ApiResponseRest, AuthStatus};

// Synthesize a GraphQL response with the given data and authentication status
pub fn synthesize_graphql_response<T: OutputType + Clone>(
    ctx: &Context<'_>,
    data: &T,
    auth_status: Option<&AuthStatus>,
) -> Option<ApiResponse<T>> {
    let header_map = ctx.data_opt::<HeaderMap>()?;
    // let new_access_token = header_map
    //     .get("new-access-token")
    //     .map(|token| token.to_str().unwrap_or("").to_owned());
    let request_id = header_map
        .get("x-request-id")
        .map(|token| token.to_str().unwrap_or("").to_owned())
        .unwrap_or_default();

    Some(ApiResponse::new(
        data,
        request_id,
        match auth_status {
            Some(status) => status.new_access_token.to_owned(),
            None => None,
        },
    ))
}

pub fn synthesize_rest_response<T: Serialize + Clone>(
    headers: &HeaderMap,
    data: &T,
    status: axum::http::StatusCode,
) -> ApiResponseRest<T> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    let new_access_token = headers
        .get("new-access-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    ApiResponseRest::new(data, status, request_id, new_access_token)
}
