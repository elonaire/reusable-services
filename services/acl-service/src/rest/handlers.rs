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
use surrealdb::{engine::remote::ws::Client, types::RecordIdKey, Surreal};
use tokio::fs;

use crate::{
    graphql::schemas::user::{
        AccountStatus, AuthDetails, GithubUserProfile, GoogleUserInfo, OAuthUser, User,
    },
    utils::auth::{
        create_oauth_user_if_not_exists, decode_token_string, decrypt_native_state,
        encrypt_for_native, fetch_user_roles, initiate_auth_code_grant_flow, sign_jwt,
        verify_oauth_token, OAuthClientName,
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

// ── Native counterpart ────────────────────────────────────────────────
//
/// Called directly by the app (not via browser redirect), so no cookies
/// are involved at all. `state` and `auth_code` are what the app got back
/// from the deep link; `encrypted_state` is the blob it's been holding
/// since the original sign_in call. Decrypting it recovers the PKCE
/// verifier and the oauth_client that was actually used, and comparing
/// its csrf to `state` is the CSRF check this flow never got to do earlier.
#[derive(serde::Deserialize)]
pub struct NativeTokenExchangeContract {
    pub auth_code: String,
    pub state: String,
    pub encrypted_state: String,
}

/// Native OAuth callback — hit by the system browser / Custom Tabs after
/// Google redirects, NOT by the app itself. There is no cookie jar shared
/// with whatever made the original `sign_in` call (e.g. if that was the Tauri
/// app's own HTTP client, a completely different context), so there is
/// nothing to verify `state` against here.
///
/// This handler's only job is to hand `code` + `state` back to the app via
/// its deep link. The app already holds the encrypted state blob it got
/// back from `sign_in` — it pairs that with this `state`/`code` and
/// completes CSRF verification + the PKCE token exchange in a separate,
/// directly-authenticated call to the backend (not a browser redirect),
/// e.g. POST /oauth/native/exchange.
pub async fn oauth_callback_native_handler(
    params: Query<Params>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!("native callback hit");
    let state = params.0.state.ok_or_else(|| {
        tracing::error!("State param is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let code = params.0.code.ok_or_else(|| {
        tracing::error!("Code param is missing!");
        ApiError::Forbidden("Forbidden".into())
    })?;

    let client_token_url = env::var("OAUTH_CLIENT_TOKEN_URL").map_err(|e| {
        tracing::error!("OAUTH_CLIENT_TOKEN_URL not set: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    // state rides along so the app can hand it back to the exchange
    // endpoint alongside its stored encrypted blob.
    Ok(Redirect::to(&format!(
        "{}?auth_code={}&state={}",
        client_token_url, code, state
    ))
    .into_response())
}

/// client agnostic oauth callback handler, cookie-based CSRF check and all, because for a
/// genuine browser web session the browser that started the flow IS the
/// browser Google redirects back to.
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

async fn complete_oauth_login(
    db: &Arc<Surreal<Client>>,
    oauth_client_name: OAuthClientName,
    token_header: &HeaderValue,
) -> Result<String, ApiError> {
    let token_expiry_duration = Duration::from_days(30);

    match oauth_client_name {
        OAuthClientName::Google => {
            let user = verify_oauth_token::<GoogleUserInfo>(OAuthClientName::Google, token_header)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to verify Google token: {}", e);
                    ApiError::Unauthorized("Unauthorized".into())
                })?;

            let created_user = create_oauth_user_if_not_exists::<Arc<Surreal<Client>>>(
                db,
                OAuthClientName::Google,
                &OAuthUser::Google(user.clone()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to create Google user: {}", e);
                ApiError::Unauthorized("Unauthorized".into())
            })?;

            let Some(user_id) = (match &created_user.id.key {
                RecordIdKey::String(s) => Some(s.clone()),
                _ => None,
            }) else {
                tracing::error!("Invalid user");
                return Err(ApiError::Unauthorized("Unauthorized".into()));
            };

            let user_roles = fetch_user_roles(db, &user_id, None).await.map_err(|e| {
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
            })
        }

        OAuthClientName::Github => {
            let user =
                verify_oauth_token::<GithubUserProfile>(OAuthClientName::Github, token_header)
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to verify GitHub token: {}", e);
                        ApiError::Unauthorized("Unauthorized".into())
                    })?;

            let created_user = create_oauth_user_if_not_exists::<Arc<Surreal<Client>>>(
                db,
                OAuthClientName::Github,
                &OAuthUser::Github(user.clone()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to create GitHub user: {}", e);
                ApiError::Unauthorized("Unauthorized".into())
            })?;

            let Some(user_id) = (match &created_user.id.key {
                RecordIdKey::String(s) => Some(s.clone()),
                _ => None,
            }) else {
                tracing::error!("Invalid user");
                return Err(ApiError::BadRequest("Bad Request".into()));
            };

            let user_roles = fetch_user_roles(db, &user_id, None).await.map_err(|e| {
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
            })
        }
    }
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

    let oauth_user_roles_jwt =
        complete_oauth_login(&db, oauth_client_name_conversion, &token_header).await?;

    cookie.add(
        CookieBuilder::new("oauth_user_roles_jwt", oauth_user_roles_jwt)
            .path("/")
            .build(),
    );

    Ok(synthesize_rest_response(
        &headers,
        &AuthDetails {
            url: None,
            token: Some(token.to_owned()),
            encrypted_state: None,
            refresh_token: None,
            oauth_client: None,
        },
        StatusCode::OK,
    ))
}

pub async fn exchange_code_for_token_native(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    headers: HeaderMap,
    Json(payload): Json<NativeTokenExchangeContract>,
) -> Result<ApiResponseRest<AuthDetails>, ApiError> {
    let native_state = decrypt_native_state(&payload.encrypted_state).map_err(|e| {
        tracing::error!("Failed to decrypt native oauth state: {:?}", e);
        ApiError::Forbidden("Forbidden".into())
    })?;

    if native_state.csrf != payload.state {
        tracing::error!("CSRF token mismatch (native)! Aborting request. Might be a hacker 🥷🏻!");
        return Err(ApiError::Forbidden("Forbidden".into()));
    }

    let oauth_client_name = native_state.oauth_client;

    let oauth_client = initiate_auth_code_grant_flow(oauth_client_name)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initiate auth code grant flow: {}", e);
            ApiError::Forbidden("Forbidden".into())
        })?;

    let pkce_verifier = PkceCodeVerifier::new(native_state.pkce_verifier);
    let auth_code = AuthorizationCode::new(payload.auth_code);

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

    // No cookie jar — encrypt the refresh token the same way the
    // password-login flow already does, and return it in the body.
    let refresh_token_body = match token_result.refresh_token() {
        Some(rt) => Some(encrypt_for_native(rt.secret()).map_err(|e| {
            tracing::error!("Failed to encrypt refresh token for native: {}", e);
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?),
        None => None,
    };

    let token = token_result.access_token().secret();
    let token_header = HeaderValue::from_str(&format!("Bearer {}", token)).map_err(|e| {
        tracing::error!("Failed to create token header: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let oauth_user_roles_jwt = complete_oauth_login(&db, oauth_client_name, &token_header).await?;

    Ok(synthesize_rest_response(
        &headers,
        &AuthDetails {
            url: None,
            // Native has nowhere else to put this — it's the token the
            // app will actually authenticate with, unlike the web flow
            // where this field holds Google's raw access token instead.
            token: Some(oauth_user_roles_jwt),
            encrypted_state: None,
            refresh_token: refresh_token_body,
            oauth_client: Some(oauth_client_name),
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

    let Some(user_id) = claims.subject else {
        return Err(ApiError::Unauthorized("Unauthorized".into()));
    };

    let _query_result: Option<User> = db
        .query(
            "
        BEGIN TRANSACTION;
        LET $user = type::record('user', $user_id);

        UPDATE $user SET status = $status RETURN AFTER;
        COMMIT TRANSACTION;
        ",
        )
        .bind(("user_id", user_id))
        .bind(("status", AccountStatus::Active))
        .await
        .map_err(|e| {
            tracing::error!("Failed to activate user account: {}", e);
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?
        .take(2)
        .map_err(|e| {
            tracing::error!("Failed to activate user account: {}", e);
            ApiError::Unauthorized("Unauthorized".into())
        })?;

    Ok(synthesize_rest_response(&headers, &(), StatusCode::OK))
}
