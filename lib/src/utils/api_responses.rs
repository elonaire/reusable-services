use async_graphql::{Context, OutputType};
use hyper::HeaderMap;

use crate::utils::models::ApiResponse;

pub fn synthesize_graphql_response<T: OutputType + Clone>(
    ctx: &Context<'_>,
    data: &T,
) -> Option<ApiResponse<T>> {
    let header_map = ctx.data_opt::<HeaderMap>()?;
    let new_access_token = header_map
        .get("new-access-token")
        .map(|token| token.to_str().unwrap_or("").to_owned());
    let request_id = header_map
        .get("x-request-id")
        .map(|token| token.to_str().unwrap_or("").to_owned())
        .unwrap_or_default();

    Some(ApiResponse::new(data, request_id, new_access_token))
}
