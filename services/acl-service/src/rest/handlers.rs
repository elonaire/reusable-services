use std::{env, sync::Arc};

use axum::{
    extract::Query,
    http::{header::COOKIE as AXUM_COOKIE, HeaderValue},
    response::{IntoResponse, Redirect},
    Extension, Json,
};
use axum_cookie::prelude::*;
use hyper::{HeaderMap, StatusCode};
use jwt_simple::prelude::Duration;
use lib::utils::{auth::AuthClaim, cookie_parser::parse_cookies};
use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use serde::{Deserialize, Serialize};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    graphql::schemas::user::{AuthDetails, GithubUserProfile, GoogleUserInfo, OAuthUser},
    utils::auth::{
        create_oauth_user_if_not_exists, fetch_default_user_roles, initiate_auth_code_grant_flow,
        sign_jwt, verify_oauth_token, OAuthClientName,
    },
};

#[derive(Debug, Deserialize, Clone)]
pub struct Params {
    pub code: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenExchangeContract {
    pub auth_code: Option<String>,
}

/// client agnostic oauth callback handler
pub async fn oauth_callback_handler(
    params: Query<Params>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // get the csrf state from the cookie
    // Extract the csrf_state, oauth_client, pkce_verifier cookies
    // Extract cookies from the headers
    let cookie_header = headers.get(AXUM_COOKIE).and_then(|v| v.to_str().ok());

    if params.0.state.is_none() || params.0.code.is_none() || cookie_header.is_none() {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    // Split and parse cookies manually
    let cookie_map: std::collections::HashMap<_, _> = parse_cookies(cookie_header.unwrap());

    // let pkce_verifier_secret = cookie_map.get("k").expect("PKCE verifier cookie not found");
    let csrf_state = cookie_map.get("j");

    if csrf_state.is_none() {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let client_token_url = env::var("OAUTH_CLIENT_TOKEN_URL");

    if let Err(e) = &client_token_url {
        tracing::error!("OAUTH_CLIENT_TOKEN_URL not set: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response();
    }

    if params.0.state.unwrap() != csrf_state.unwrap().to_owned() {
        tracing::error!("CSRF token mismatch! Aborting request. Might be a hacker 🥷🏻!");
        panic!("CSRF token mismatch! Aborting request. Might be a hacker 🥷🏻!");
    }

    Redirect::to(&format!(
        "{}?auth_code={}",
        client_token_url.unwrap(),
        params.0.code.clone().unwrap()
    ))
    .into_response()
}

pub async fn exchange_code_for_token(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    cookie: CookieManager,
    Json(payload): Json<TokenExchangeContract>,
) -> Result<Json<AuthDetails>, StatusCode> {
    let cookie_header = headers.get(AXUM_COOKIE).and_then(|v| v.to_str().ok());

    if cookie_header.is_none() || payload.auth_code.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    // Split and parse cookies manually
    let cookie_map: std::collections::HashMap<_, _> = parse_cookies(cookie_header.unwrap());

    let pcke_verifier_secret = cookie_map.get("k");

    let oauth_client_name = cookie_map.get("oauth_client");

    if pcke_verifier_secret.is_none() || oauth_client_name.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    let oauth_client_name_conversion = OAuthClientName::from_str(oauth_client_name.unwrap());

    // We need to get the same client instance that we used to generate the auth url. Hence the cookies.
    let oauth_client = initiate_auth_code_grant_flow(oauth_client_name_conversion)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initiate auth code grant flow: {}", e);
            StatusCode::FORBIDDEN
        })?;

    // Generate a PKCE verifier using the secret.
    let pkce_verifier = PkceCodeVerifier::new(pcke_verifier_secret.unwrap().to_owned());
    let auth_code = AuthorizationCode::new(payload.auth_code.unwrap());

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build HTTP Client: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // // Now you can trade it for an access token.
    let token_result = oauth_client
        .exchange_code(auth_code)
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to exchange code for token: {}", e);
            StatusCode::FORBIDDEN
        })?;

    let token = token_result.access_token().secret();

    let token_header = HeaderValue::from_str(&format!("Bearer {}", token)).map_err(|e| {
        tracing::error!("Failed to create token header: {}", e);
        StatusCode::FORBIDDEN
    })?;
    let token_expiry_duration = Duration::from_secs(30 * 24 * 60 * 60); // days by hours by minutes by 60 seconds

    match oauth_client_name_conversion {
        OAuthClientName::Google => {
            let user = verify_oauth_token::<GoogleUserInfo>(OAuthClientName::Google, &token_header)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to verify Google token: {}", e);
                    StatusCode::UNAUTHORIZED
                })?;

            let _create_user = create_oauth_user_if_not_exists::<Arc<Surreal<Client>>>(
                &db,
                OAuthClientName::Google,
                &OAuthUser::Google(user.clone()),
            )
            .await;

            let user_roles = fetch_default_user_roles(&db, &user.resource_name)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to fetch default roles: {}", e);
                    StatusCode::UNAUTHORIZED
                })?;

            let auth_claim = AuthClaim {
                roles: user_roles.to_vec(),
            };

            let token_str = sign_jwt(&auth_claim, token_expiry_duration, &user.resource_name)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to sign JWT: {}", e);
                    StatusCode::UNAUTHORIZED
                })?;

            let jwt_cookie = CookieBuilder::new("oauth_user_roles_jwt", token_str.clone())
                .path("/")
                .build();

            cookie.add(jwt_cookie);

            Ok((AuthDetails {
                url: None,
                token: Some(token_str),
            })
            .into())
        }
        OAuthClientName::Github => {
            let user =
                verify_oauth_token::<GithubUserProfile>(OAuthClientName::Github, &token_header)
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to verify GitHub token: {}", e);
                        StatusCode::UNAUTHORIZED
                    })?;

            let _create_user = create_oauth_user_if_not_exists::<Arc<Surreal<Client>>>(
                &db,
                OAuthClientName::Github,
                &OAuthUser::Github(user.clone()),
            )
            .await;

            let user_roles = fetch_default_user_roles(&db, &user.id.to_string())
                .await
                .map_err(|e| {
                    tracing::error!("Failed to fetch user roles: {}", e);
                    StatusCode::UNAUTHORIZED
                })?;

            let auth_claim = AuthClaim {
                roles: user_roles.to_vec(),
            };

            let token_str = sign_jwt(&auth_claim, token_expiry_duration, &user.id.to_string())
                .await
                .map_err(|e| {
                    tracing::error!("Failed to sign JWT: {}", e);
                    StatusCode::UNAUTHORIZED
                })?;

            let jwt_cookie = CookieBuilder::new("oauth_user_roles_jwt", token_str.clone())
                .path("/")
                .build();

            cookie.add(jwt_cookie);

            Ok((AuthDetails {
                url: None,
                token: Some(token_str),
            })
            .into())
        }
    }
}
