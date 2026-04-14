use std::{env, sync::Arc};

use axum::{
    extract::Query,
    http::{header::COOKIE as AXUM_COOKIE, HeaderValue},
    response::{IntoResponse, Redirect},
    Extension, Json,
};
use axum_cookie::prelude::*;
use base64::{engine::general_purpose, Engine as _engine};
use hyper::{HeaderMap, StatusCode};
use jwt_simple::prelude::Duration;
use lib::utils::{
    api_responses::synthesize_rest_response, auth::AuthClaim, cookie_parser::parse_cookies,
    custom_error::ApiError, models::ApiResponseRest,
};
use oauth2::{AuthorizationCode, PkceCodeVerifier, TokenResponse};
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Encrypt, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use surrealdb::{engine::remote::ws::Client, Surreal};
use tokio::fs;

use crate::{
    graphql::schemas::user::{AuthDetails, GithubUserProfile, GoogleUserInfo, OAuthUser},
    utils::auth::{
        create_oauth_user_if_not_exists, decode_token_string, fetch_user_roles,
        initiate_auth_code_grant_flow, sign_jwt, verify_oauth_token, OAuthClientName,
    },
};

#[derive(Debug, Deserialize, Clone)]
pub struct Params {
    pub code: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailVerificationParams {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TokenExchangeContract {
    pub auth_code: Option<String>,
}

/// client agnostic oauth callback handler
pub async fn oauth_callback_handler(
    params: Query<Params>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let cookie_header = headers
        .get(AXUM_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!("Cookie header is missing!");
            ApiError::Forbidden("Forbidden".into())
        })?;

    let state = params.0.state.ok_or_else(|| {
        tracing::error!("State param is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let code = params.0.code.ok_or_else(|| {
        tracing::error!("Code param is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let cookie_map = parse_cookies(cookie_header);

    let csrf_state = cookie_map.get("j").ok_or_else(|| {
        tracing::error!("csrf_state(j) cookie is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let client_token_url = env::var("OAUTH_CLIENT_TOKEN_URL").map_err(|e| {
        tracing::error!("OAUTH_CLIENT_TOKEN_URL not set: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    if state != *csrf_state {
        tracing::error!("CSRF token mismatch! Aborting request. Might be a hacker 🥷🏻!");
        return Err(ApiError::Forbidden("Forbidden".into()));
    }

    Ok(Redirect::to(&format!("{}?auth_code={}", client_token_url, code)).into_response())
}

pub async fn exchange_code_for_token(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    cookie: CookieManager,
    Json(payload): Json<TokenExchangeContract>,
) -> Result<ApiResponseRest<AuthDetails>, ApiError> {
    let cookie_header = headers
        .get(AXUM_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::error!("Cookie header is missing!");
            ApiError::Forbidden("Forbidden".into())
        })?;

    let auth_code = payload.auth_code.ok_or_else(|| {
        tracing::error!("Auth code is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let cookie_map = parse_cookies(cookie_header);

    let pkce_verifier_secret = cookie_map.get("k").ok_or_else(|| {
        tracing::error!("PKCE verifier cookie(k) is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let oauth_client_name = cookie_map.get("oauth_client").ok_or_else(|| {
        tracing::error!("OAuth client cookie is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let oauth_client_name_conversion = OAuthClientName::from_str(oauth_client_name);

    let oauth_client = initiate_auth_code_grant_flow(oauth_client_name_conversion)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initiate auth code grant flow: {}", e);
            ApiError::Forbidden("Forbidden".into())
        })?;

    let pkce_verifier = PkceCodeVerifier::new(pkce_verifier_secret.to_owned());
    let auth_code = AuthorizationCode::new(auth_code);

    let http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build Reqwest client: {}", e);
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;

    let token_result = oauth_client
        .exchange_code(auth_code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to exchange code for token: {}", e);
            ApiError::Forbidden("Forbidden".into())
        })?;

    if let Some(refresh_token) = token_result.refresh_token() {
        cookie.add(
            CookieBuilder::new("t", refresh_token.secret().to_owned())
                .path("/")
                .build(),
        );
    }

    let token = token_result.access_token().secret();

    let token_header = HeaderValue::from_str(&format!("Bearer {}", token)).map_err(|e| {
        tracing::error!("Failed to create token header: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let token_expiry_duration = Duration::from_secs(30 * 24 * 60 * 60);

    let token_str = match oauth_client_name_conversion {
        OAuthClientName::Google => {
            let user = verify_oauth_token::<GoogleUserInfo>(OAuthClientName::Google, &token_header)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to verify Google token: {}", e);
                    ApiError::Unauthorized("Unauthorized".into())
                })?;

            let created_user = create_oauth_user_if_not_exists::<Arc<Surreal<Client>>>(
                &db,
                OAuthClientName::Google,
                &OAuthUser::Google(user.clone()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to create Google user: {}", e);
                ApiError::Unauthorized("Unauthorized".into())
            })?;

            let user_roles = fetch_user_roles(&db, &created_user.id.key().to_string(), None)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to fetch Google user roles: {}", e);
                    ApiError::Unauthorized("Unauthorized".into())
                })?;

            sign_jwt(
                &AuthClaim {
                    roles: user_roles.to_vec(),
                },
                token_expiry_duration,
                &user.sub,
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to sign Google JWT: {}", e);
                ApiError::Unauthorized("Unauthorized".into())
            })?
        }

        OAuthClientName::Github => {
            let user =
                verify_oauth_token::<GithubUserProfile>(OAuthClientName::Github, &token_header)
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to verify GitHub token: {}", e);
                        ApiError::Unauthorized("Unauthorized".into())
                    })?;

            let created_user = create_oauth_user_if_not_exists::<Arc<Surreal<Client>>>(
                &db,
                OAuthClientName::Github,
                &OAuthUser::Github(user.clone()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to create GitHub user: {}", e);
                ApiError::Unauthorized("Unauthorized".into())
            })?;

            let user_roles = fetch_user_roles(&db, &created_user.id.key().to_string(), None)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to fetch GitHub user roles: {}", e);
                    ApiError::Unauthorized("Unauthorized".into())
                })?;

            sign_jwt(
                &AuthClaim {
                    roles: user_roles.to_vec(),
                },
                token_expiry_duration,
                &user.id.to_string(),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to sign GitHub JWT: {}", e);
                ApiError::Unauthorized("Unauthorized".into())
            })?
        }
    };

    cookie.add(
        CookieBuilder::new("oauth_user_roles_jwt", token_str)
            .path("/")
            .build(),
    );

    Ok(synthesize_rest_response(
        &headers,
        &AuthDetails {
            url: None,
            token: Some(token.to_owned()),
        },
        StatusCode::OK,
    ))
}

pub async fn verify_email_handler(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    params: Query<EmailVerificationParams>,
) -> Result<ApiResponseRest<()>, ApiError> {
    let token = params.0.token.ok_or_else(|| {
        tracing::error!("Token param is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let private_key_path = env::var("RSA_PRIVATE_KEY_PATH").map_err(|e| {
        tracing::error!("Failed to get RSA_PRIVATE_KEY_PATH env var: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let private_key_file = fs::read_to_string(&private_key_path).await.map_err(|e| {
        tracing::error!("Failed to read private key file: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_file).map_err(|e| {
        tracing::error!("Failed to parse private key: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let decoded_token = general_purpose::URL_SAFE_NO_PAD
        .decode(&token)
        .map_err(|e| {
            tracing::error!("Failed to decode token: {}", e);
            ApiError::BadRequest("Bad Request".into())
        })?;

    let decrypted_token = private_key
        .decrypt(Pkcs1v15Encrypt, &decoded_token)
        .map_err(|e| {
            tracing::error!("Failed to decrypt token: {}", e);
            ApiError::BadRequest("Bad Request".into())
        })?;

    let signed_jwt = String::from_utf8(decrypted_token).map_err(|e| {
        tracing::error!("Failed to create signed JWT: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let claims = decode_token_string(&signed_jwt).await.map_err(|e| {
        tracing::error!("Failed to decode token: {}", e);
        ApiError::Unauthorized("Unauthorized".into())
    })?;

    let user_id = claims
        .subject
        .as_ref()
        .map(|t| t.to_string())
        .unwrap_or_default();

    db.query(
        "
        BEGIN TRANSACTION;
        LET $user = type::thing('user', $user_id);
        IF !$user.exists() {
            THROW 'Invalid Input';
        };
        UPDATE $user SET status = 'Active';
        COMMIT TRANSACTION;
        ",
    )
    .bind(("user_id", user_id))
    .await
    .map_err(|e| {
        tracing::error!("Failed to activate user account: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    Ok(synthesize_rest_response(&headers, &(), StatusCode::OK))
}
