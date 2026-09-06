use axum::http::HeaderValue;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use cookie::time::OffsetDateTime;
use jwt_simple::prelude::*;
use lib::utils::custom_traits::AuthMetadataContext;
use lib::utils::models::AuthorizationConstraint;
use lib::utils::{
    auth::AuthClaim, cookie_parser::parse_cookies, custom_traits::AsSurrealClient,
    models::AuthStatus,
};
use std::env;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
};
use surrealdb::types::{RecordIdKey, SurrealValue};
use tokio::fs;

use async_graphql::{Context, Enum};
use base64::{engine::general_purpose, Engine as _engine};
use hyper::{
    header::{COOKIE, SET_COOKIE},
    Method,
};
use oauth2::{
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
    EndpointNotSet, EndpointSet,
};
use reqwest::{header::HeaderMap as ReqWestHeaderMap, Client as ReqWestClient};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge,
    RedirectUrl, RefreshToken, RevocationErrorResponseType, RevocationUrl, Scope,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::graphql::schemas::user::{
    AccountStatus, ApiKey, ClientPlatform, GithubUserProfile, OAuthTokenPair, User, UserInput,
    UserLogins,
};
use crate::graphql::schemas::user::{GoogleUserInfo, OAuthUser};
use crate::utils::user::create_user;

pub type OAuthClientInstance = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum OAuthFlow {
    AuthCodeGrant,
    ClientCredentials,
    ResourceOwnerPassword,
    DeviceCode,
    RefreshToken,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq, SurrealValue)]
pub enum OAuthClientName {
    #[graphql(name = "Google")]
    Google,
    #[graphql(name = "Github")]
    Github,
}

impl OAuthClientName {
    fn fmt(&self) -> String {
        match self {
            OAuthClientName::Google => format!("Google"),
            OAuthClientName::Github => format!("Github"),
        }
    }

    pub fn from_str(s: &str) -> OAuthClientName {
        match s {
            "Google" => OAuthClientName::Google,
            "Github" => OAuthClientName::Github,
            _ => panic!("Invalid OAuthClientName"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NativeOAuthState {
    pub csrf: String,
    pub pkce_verifier: String,
    pub oauth_client: OAuthClientName,
    pub issued_at: i64, // unix seconds
}

const NATIVE_OAUTH_STATE_TTL_SECS: i64 = 120; // same window the cookies' Max-Age gave

fn load_rsa_public_key() -> Result<RsaPublicKey, Error> {
    let public_key_path = env::var("RSA_PUBLIC_KEY_PATH").map_err(|e| {
        tracing::error!("Failed to get RSA_PUBLIC_KEY_PATH env var: {}", e);
        Error::new(ErrorKind::Other, "Internal Server Error")
    })?;
    let public_key_str = std::fs::read_to_string(&public_key_path).map_err(|e| {
        tracing::error!("Failed to read public key: {}", e);
        Error::new(ErrorKind::Other, "Internal Server Error")
    })?;
    RsaPublicKey::from_public_key_pem(&public_key_str).map_err(|e| {
        tracing::error!("Failed to parse public key: {}", e);
        Error::new(ErrorKind::Other, "Internal Server Error")
    })
}

fn load_rsa_private_key() -> Result<RsaPrivateKey, Error> {
    let private_key_path = env::var("RSA_PRIVATE_KEY_PATH").map_err(|e| {
        tracing::error!("Failed to get RSA_PRIVATE_KEY_PATH env var: {}", e);
        Error::new(ErrorKind::Other, "Internal Server Error")
    })?;
    let private_key_str = std::fs::read_to_string(&private_key_path).map_err(|e| {
        tracing::error!("Failed to read private key: {}", e);
        Error::new(ErrorKind::Other, "Internal Server Error")
    })?;
    RsaPrivateKey::from_pkcs8_pem(&private_key_str).map_err(|e| {
        tracing::error!("Failed to parse private key: {}", e);
        Error::new(ErrorKind::Other, "Internal Server Error")
    })
}

fn encrypt_native_state(payload: &NativeOAuthState) -> Result<String, Error> {
    let public_key = load_rsa_public_key()?;

    let json = serde_json::to_vec(payload).map_err(|e| {
        tracing::error!("Failed to serialize native oauth state: {}", e);
        Error::new(ErrorKind::Other, "Internal Server Error")
    })?;

    let mut rng = rand::rngs::OsRng;
    let encrypted = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &json)
        .map_err(|e| {
            tracing::error!("Failed to encrypt native oauth state: {}", e);
            Error::new(ErrorKind::Other, "Internal Server Error")
        })?;

    Ok(URL_SAFE_NO_PAD.encode(&encrypted[..]))
}

// Callback-side counterpart — for the /oauth/callback handler when it sees
// a native request.
pub fn decrypt_native_state(blob: &str) -> Result<NativeOAuthState, Error> {
    let private_key = load_rsa_private_key()?;

    let encrypted = URL_SAFE_NO_PAD.decode(blob).map_err(|e| {
        tracing::error!("Failed to base64-decode native oauth state: {}", e);
        Error::new(ErrorKind::Other, "Bad Request")
    })?;

    let plaintext = private_key
        .decrypt(Pkcs1v15Encrypt, &encrypted)
        .map_err(|e| {
            tracing::error!("Failed to decrypt native oauth state: {}", e);
            Error::new(ErrorKind::Other, "Bad Request")
        })?;

    let payload: NativeOAuthState = serde_json::from_slice(&plaintext).map_err(|e| {
        tracing::error!("Failed to deserialize native oauth state: {}", e);
        Error::new(ErrorKind::Other, "Bad Request")
    })?;

    let age = OffsetDateTime::now_utc().unix_timestamp() - payload.issued_at;
    if age > NATIVE_OAUTH_STATE_TTL_SECS {
        tracing::warn!("Native oauth state expired ({}s old)", age);
        return Err(Error::new(ErrorKind::Other, "Bad Request"));
    }

    Ok(payload)
}

// ── Generalized for reuse outside the GraphQL resolver ──────────────────
// (REST handlers use ApiError, not ExtendedError — these return
// anyhow::Result so each call site maps to its own error type.)

pub fn encrypt_for_native(plaintext: &str) -> anyhow::Result<String> {
    let public_key_path = env::var("RSA_PUBLIC_KEY_PATH")?;
    let public_key_str = std::fs::read_to_string(&public_key_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_str)?;

    let mut rng = rand::rngs::OsRng;
    let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes())?;
    Ok(URL_SAFE_NO_PAD.encode(&encrypted[..]))
}

/// Creates a desired OAuthClient of choice. For now GitHub and Google
pub async fn initiate_auth_code_grant_flow(
    oauth_client: OAuthClientName,
) -> Result<OAuthClientInstance, Error> {
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = match oauth_client {
        OAuthClientName::Google => BasicClient::new(ClientId::new(
            env::var("GOOGLE_OAUTH_CLIENT_ID").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        ))
        .set_client_secret(ClientSecret::new(
            env::var("GOOGLE_OAUTH_CLIENT_SECRET").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        ))
        .set_auth_uri(
            AuthUrl::new(env::var("GOOGLE_OAUTH_AUTHORIZE_URL").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?)
            .map_err(|e| {
                tracing::error!("Failed to create AuthUrl.: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        )
        .set_token_uri(
            TokenUrl::new(env::var("GOOGLE_OAUTH_ACCESS_TOKEN_URL").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?)
            .map_err(|e| {
                tracing::error!("Failed to create TokenUrl.: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        )
        .set_revocation_url(
            RevocationUrl::new(env::var("GOOGLE_OAUTH_REVOKE_TOKEN_URL").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?)
            .map_err(|e| {
                tracing::error!("Invalid RevocationUrl: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        ),
        OAuthClientName::Github => BasicClient::new(ClientId::new(
            env::var("GITHUB_OAUTH_CLIENT_ID").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        ))
        .set_client_secret(ClientSecret::new(
            env::var("GITHUB_OAUTH_CLIENT_SECRET").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        ))
        .set_auth_uri(
            AuthUrl::new(env::var("GITHUB_OAUTH_AUTHORIZE_URL").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?)
            .map_err(|e| {
                tracing::error!("Failed to create AuthUrl.: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        )
        .set_token_uri(
            TokenUrl::new(env::var("GITHUB_OAUTH_ACCESS_TOKEN_URL").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?)
            .map_err(|e| {
                tracing::error!("Failed to create TokenUrl.: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        )
        .set_revocation_url(
            RevocationUrl::new(env::var("GITHUB_OAUTH_REVOKE_TOKEN_URL").map_err(|e| {
                tracing::error!("Config Error: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?)
            .map_err(|e| {
                tracing::error!("Failed to create RevocationUrl.: {}", e);
                Error::new(ErrorKind::Other, "Server Error")
            })?,
        ),
    };

    Ok(client.set_redirect_uri(
        RedirectUrl::new(env::var("OAUTH_REDIRECT_URI").map_err(|e| {
            tracing::error!("Config Error: {}", e);
            Error::new(ErrorKind::Other, "Server Error")
        })?)
        .map_err(|e| {
            tracing::error!("Failed to create RedirectUrl.: {}", e);
            Error::new(ErrorKind::Other, "Server Error")
        })?,
    ))
}

// Generates a Redirect url for the OAuth Code Grant Flow
pub async fn navigate_to_redirect_url(
    oauth_client: OAuthClientInstance,
    ctx: &Context<'_>,
    oauth_client_name: OAuthClientName,
    platform: ClientPlatform,
) -> Result<(String, Option<String>), Error> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let auth_request = match oauth_client_name {
        OAuthClientName::Google => oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            )),
        OAuthClientName::Github => oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("read:user".to_string())),
    };

    let (auth_url, csrf_token) = auth_request.set_pkce_challenge(pkce_challenge).url();

    match platform {
        ClientPlatform::Web => {
            ctx.insert_http_header(
                SET_COOKIE,
                format!(
                    "oauth_client={}; HttpOnly; SameSite=Strict; Path=/; Secure",
                    oauth_client_name.fmt()
                ),
            );
            let sensitive_cookies_expiry_duration = Duration::from_secs(120);
            ctx.append_http_header(
                SET_COOKIE,
                format!(
                    "j={}; Max-Age={}; HttpOnly; SameSite=Strict; Path=/; Secure",
                    csrf_token.secret(),
                    sensitive_cookies_expiry_duration.as_secs()
                ),
            );
            ctx.append_http_header(
                SET_COOKIE,
                format!(
                    "k={}; Max-Age={}; HttpOnly; SameSite=Strict; Path=/; Secure",
                    pkce_verifier.secret(),
                    sensitive_cookies_expiry_duration.as_secs()
                ),
            );
            Ok((auth_url.to_string(), None))
        }
        ClientPlatform::Native => {
            let payload = NativeOAuthState {
                csrf: csrf_token.secret().clone(),
                pkce_verifier: pkce_verifier.secret().clone(),
                oauth_client: oauth_client_name,
                issued_at: OffsetDateTime::now_utc().unix_timestamp(),
            };
            let state_blob = encrypt_native_state(&payload)?;
            Ok((auth_url.to_string(), Some(state_blob)))
        }
    }
}

/// A utility function to decode JWT tokens. Returns full claims
pub async fn decode_token(token_header: &HeaderValue) -> Result<JWTClaims<AuthClaim>, Error> {
    let token = (token_header.to_str().map_err(|e| {
        tracing::error!("Failed to convert header to str: {}", e);
        Error::new(ErrorKind::InvalidData, "Unauthorized!")
    })?)
    .strip_prefix("Bearer ");

    match token {
        Some(token) => {
            let converted_jwt_secret_key = get_converted_jwt_secret_key().await?;

            let claims_result = converted_jwt_secret_key.verify_token::<AuthClaim>(&token, None);

            match claims_result {
                Ok(claims) => {
                    // Token verification successful
                    Ok(claims)
                }
                Err(e) => {
                    tracing::error!("Token verification failed: {}", e);
                    Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "Token verification failed",
                    ))
                }
            }
        }
        None => Err(Error::new(ErrorKind::Other, "Invalid token format")),
    }
}

/// A utility function to decode JWT tokens(String Args). Returns full claims
pub async fn decode_token_string(token: &String) -> Result<JWTClaims<AuthClaim>, Error> {
    let converted_jwt_secret_key = get_converted_jwt_secret_key().await?;

    let claims_result = converted_jwt_secret_key.verify_token::<AuthClaim>(&token, None);

    match claims_result {
        Ok(claims) => {
            // Token verification successful
            Ok(claims)
        }
        Err(e) => {
            tracing::error!("Token verification failed: {}", e);
            Err(Error::new(
                ErrorKind::PermissionDenied,
                "Token verification failed",
            ))
        }
    }
}

/// A utility function to confirm auth by parsing relevant headers. Useful for authenticating clients. Includes refresh token handling and OAuth
pub async fn confirm_authentication<T, C>(db: &T, ctx: &C) -> Result<AuthStatus, Error>
where
    T: Clone + AsSurrealClient,
    C: AuthMetadataContext + Sync,
{
    let metadata_view = ctx.request_metadata();
    let header_map = metadata_view.as_header_map().ok_or_else(|| {
        tracing::error!("Invalid request headers!");
        Error::new(ErrorKind::Other, "Invalid request!")
    })?;

    let token = header_map.get("Authorization").ok_or_else(|| {
        tracing::error!("Missing access token!");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    let cookie_header = header_map.get(COOKIE).ok_or_else(|| {
        tracing::error!("Missing cookie headers!");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    let cookies_str = cookie_header.to_str().map_err(|e| {
        tracing::error!("Invalid cookie format: {:?}", e);
        Error::new(ErrorKind::InvalidData, "Invalid request!")
    })?;

    let cookies = parse_cookies(cookies_str);

    let oauth_client = cookies.get("oauth_client").ok_or_else(|| {
        tracing::error!("Missing oauth client id!");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    // Normal auth flow
    if oauth_client.is_empty() {
        return match cookies.get("t") {
            Some(_auth_cookie) => handle_normal_auth(token, &cookies, db, ctx).await,
            None => handle_api_key_auth(token, db).await,
        };
    }

    // OAuth flow
    handle_oauth_auth(token, &cookies, oauth_client, db, ctx).await
}

async fn handle_normal_auth<T, C>(
    token: &HeaderValue,
    cookies: &HashMap<String, String>,
    db: &T,
    ctx: &C,
) -> Result<AuthStatus, Error>
where
    T: Clone + AsSurrealClient,
    C: AuthMetadataContext + Sync,
{
    match decode_token(token).await {
        Ok(claims) => {
            let Some(sub) = claims.subject else {
                return Err(Error::new(ErrorKind::Other, "Unauthorized!"));
            };

            let sub_ref = &sub;
            if claims.custom.roles.is_empty() {
                tracing::error!("Token role claims are empty");
                return Err(Error::new(ErrorKind::InvalidData, "Unauthorized!"));
            }
            let current_role = claims.custom.roles[0].clone();

            let current_role_permissions =
                fetch_current_role_permissions(db, sub_ref, &current_role).await?;

            Ok(AuthStatus {
                is_auth: true,
                sub,
                current_role,
                new_access_token: None,
                current_role_permissions,
            })
        }
        Err(_) => handle_refresh_token(cookies, db, ctx).await,
    }
}

async fn handle_oauth_auth<T, C>(
    token: &HeaderValue,
    cookies: &HashMap<String, String>,
    oauth_client: &str,
    db: &T,
    ctx: &C,
) -> Result<AuthStatus, Error>
where
    T: Clone + AsSurrealClient,
    C: AuthMetadataContext + Sync,
{
    let oauth_user_roles_jwt = cookies.get("oauth_user_roles_jwt").ok_or_else(|| {
        tracing::error!("Missing oauth user permissions jwt!");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    let jwt_header =
        HeaderValue::from_str(&format!("Bearer {oauth_user_roles_jwt}")).map_err(|e| {
            tracing::error!("Failed to convert str to headervalue: {}", e);
            Error::new(ErrorKind::InvalidData, "Unauthorized!")
        })?;

    let claims = decode_token(&jwt_header).await.map_err(|e| {
        tracing::error!("Failed to decode jwt! - {e}");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    let oauth_client_name = OAuthClientName::from_str(oauth_client);
    let current_role = claims.custom.roles[0].clone();

    match oauth_client_name {
        OAuthClientName::Google => {
            match verify_oauth_token::<GoogleUserInfo>(OAuthClientName::Google, token).await {
                Ok(user) => {
                    let user_id_ref = &user.sub;
                    let current_role_permissions =
                        fetch_current_role_permissions(db, user_id_ref, &current_role).await?;

                    Ok(AuthStatus {
                        is_auth: true,
                        sub: user_id_ref.to_owned(),
                        current_role: claims.custom.roles[0].clone(),
                        new_access_token: None,
                        current_role_permissions,
                    })
                }
                Err(e) => {
                    tracing::error!("Error Refreshing Google Token: {e:?}");
                    handle_oauth_refresh_token(cookies, db, ctx).await
                }
            }
        }
        OAuthClientName::Github => {
            match verify_oauth_token::<GithubUserProfile>(OAuthClientName::Github, token).await {
                Ok(user) => {
                    let user_id_ref = &user.id.to_string();
                    let current_role_permissions =
                        fetch_current_role_permissions(db, user_id_ref, &current_role).await?;

                    Ok(AuthStatus {
                        is_auth: true,
                        sub: user_id_ref.to_string(),
                        current_role: claims.custom.roles[0].clone(),
                        new_access_token: None,
                        current_role_permissions,
                    })
                }
                Err(e) => {
                    tracing::error!("Error Refreshing GitHub Token: {e:?}");
                    handle_oauth_refresh_token(cookies, db, ctx).await
                }
            }
        }
    }
}

async fn handle_api_key_auth<T>(token: &HeaderValue, db: &T) -> Result<AuthStatus, Error>
where
    T: Clone + AsSurrealClient,
{
    let token_str = token
        .to_str()
        .map_err(|e| {
            tracing::error!("Failed to convert header to str: {}", e);
            Error::new(ErrorKind::InvalidData, "Unauthorized!")
        })?
        .strip_prefix("Bearer ")
        .map(|s| s.to_owned());

    match token_str {
        Some(valid_token) => {
            let Some((key_prefix, secret)) = valid_token.split_once('.') else {
                return Err(Error::new(ErrorKind::InvalidData, "Unauthorized!"));
            };

            let key_prefix = key_prefix.to_owned();
            let secret = secret.to_owned();

            let query = r#"
                (SELECT * FROM ONLY api_key WHERE key_prefix = $key_prefix AND status = 'Active' LIMIT 1 FETCH owner);

                (SELECT (->assigned->role.role_name) AS current_role FROM ONLY api_key WHERE key_prefix = $key_prefix AND status = 'Active' LIMIT 1)['current_role'][0];

                (SELECT (->assigned->role->granted->permission.name) AS current_permissions FROM ONLY api_key WHERE key_prefix = $key_prefix AND status = 'Active' LIMIT 1)['current_permissions'];
            "#;

            let mut query_result = db
                .as_client()
                .query(query)
                .bind(("key_prefix", key_prefix.clone()))
                .await
                .map_err(|e| {
                    tracing::error!("{}", e);
                    Error::new(ErrorKind::Other, "Database query failed")
                })?;

            // Get the first result from the first query
            let response: Option<ApiKey> = query_result.take(0).map_err(|e| {
                tracing::error!("Database query deserialization failed: {}", e);
                Error::new(ErrorKind::Other, "Database query deserialization failed")
            })?;

            match response {
                Some(api_key) => {
                    if !bcrypt::verify(&secret, &api_key.secret_hash).map_err(|e| {
                        tracing::error!("Failed to verify user credentials: {}", e);
                        Error::new(ErrorKind::PermissionDenied, "Invalid API Key")
                    })? {
                        return Err(Error::new(ErrorKind::PermissionDenied, "Forbidden!"));
                    }

                    let current_role_response: Option<String> =
                        query_result.take(1).map_err(|e| {
                            tracing::error!("Database query deserialization failed: {}", e);
                            Error::new(ErrorKind::Other, "Database query deserialization failed")
                        })?;

                    let current_permissions_response: Vec<String> =
                        query_result.take(2).map_err(|e| {
                            tracing::error!("Database query deserialization failed: {}", e);
                            Error::new(ErrorKind::Other, "Database query deserialization failed")
                        })?;

                    let Some(current_role) = current_role_response else {
                        return Err(Error::new(ErrorKind::PermissionDenied, "Forbidden!"));
                    };

                    let now_utc = Utc::now().to_rfc3339();

                    let query = r#"
                        UPDATE api_key SET last_used_at = $now_utc WHERE key_prefix = $key_prefix AND status = 'Active' RETURN NONE
                    "#;

                    let _query_result = db
                        .as_client()
                        .query(query)
                        .bind(("key_prefix", key_prefix))
                        .bind(("now_utc", now_utc))
                        .await
                        .map_err(|e| {
                            tracing::error!("{}", e);
                            Error::new(ErrorKind::Other, "Database query failed")
                        })?;

                    let Some(owner_id) = (match &api_key.owner.id.key {
                        RecordIdKey::String(s) => Some(s.clone()),
                        _ => None,
                    }) else {
                        tracing::error!("Invalid user");
                        return Err(Error::new(ErrorKind::Other, "Bad Request"));
                    };

                    Ok(AuthStatus {
                        is_auth: true,
                        sub: owner_id,
                        current_role,
                        new_access_token: None,
                        current_role_permissions: current_permissions_response,
                    })
                }
                None => Err(Error::new(ErrorKind::InvalidData, "Unauthorized!")),
            }
        }
        None => Err(Error::new(ErrorKind::InvalidData, "Unauthorized!")),
    }
}

/// A utility function to handle refresh tokens
async fn handle_refresh_token<T, C>(
    cookies: &HashMap<String, String>,
    db: &T,
    ctx: &C,
) -> Result<AuthStatus, Error>
where
    T: Clone + AsSurrealClient,
    C: AuthMetadataContext + Sync,
{
    let converted_jwt_secret_key = get_converted_jwt_secret_key().await?;
    match cookies.get("t") {
        Some(refresh_token) => {
            let private_key_path = env::var("RSA_PRIVATE_KEY_PATH").map_err(|e| {
                tracing::error!("Failed to get RSA_PRIVATE_KEY_PATH env var: {}", e);
                Error::new(ErrorKind::Other, "Unauthorized!")
            })?;

            let private_key_file = fs::read_to_string(&private_key_path).await.map_err(|e| {
                tracing::error!("Failed to read private key file: {}", e);
                Error::new(ErrorKind::Other, "Unauthorized!")
            })?;

            let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_file).map_err(|e| {
                tracing::error!("Failed to parse private key: {}", e);
                Error::new(ErrorKind::Other, "Unauthorized!")
            })?;

            let decoded_token = general_purpose::URL_SAFE_NO_PAD
                .decode(refresh_token)
                .map_err(|e| {
                    tracing::error!("Failed to decode token: {}", e);
                    Error::new(ErrorKind::Other, "Unauthorized!")
                })?;

            let decrypted_token = private_key
                .decrypt(Pkcs1v15Encrypt, &decoded_token)
                .map_err(|e| {
                    tracing::error!("Failed to decrypt token: {}", e);
                    Error::new(ErrorKind::Other, "Unauthorized!")
                })?;

            let signed_refresh_token = String::from_utf8(decrypted_token).map_err(|e| {
                tracing::error!("Failed to create signed JWT: {}", e);
                Error::new(ErrorKind::Other, "Unauthorized!")
            })?;

            let refresh_claims =
                converted_jwt_secret_key.verify_token::<AuthClaim>(&signed_refresh_token, None);

            match refresh_claims {
                Ok(refresh_claims) => {
                    let Some(sub) = refresh_claims.subject else {
                        return Err(Error::new(ErrorKind::Other, "Unauthorized!"));
                    };

                    let sub_ref = &sub;
                    let current_roles = refresh_claims.custom.roles;

                    tracing::debug!("current_roles: {:?}", current_roles);

                    let user: Option<User> = db
                        .as_client()
                        .select(("user", sub_ref.clone()))
                        .await
                        .map_err(|e| {
                            tracing::error!("User deserialization failed: {:?}", e);
                            Error::new(ErrorKind::Other, "User deserialization failed")
                        })?;

                    match user {
                        Some(user) => {
                            let auth_claim = AuthClaim {
                                roles: current_roles.to_vec(),
                            };

                            let Some(user_id) = (match &user.id.key {
                                RecordIdKey::String(s) => Some(s.clone()),
                                _ => None,
                            }) else {
                                tracing::error!("Invalid user");
                                return Err(Error::new(ErrorKind::Other, "Bad Request"));
                            };

                            let token_expiry_duration = Duration::from_secs(1 * 60);
                            let token = sign_jwt(&auth_claim, token_expiry_duration, &user_id)
                                .await
                                .map_err(|e| {
                                    tracing::error!("Error: {}", e);
                                    Error::new(ErrorKind::PermissionDenied, "Unauthorized")
                                })?;

                            // Set response headers using the AuthMetadataContext trait - works for REST, gRPC, and GraphQL!
                            ctx.set_response_metadata(
                                "set-cookie",
                                "oauth_client=; HttpOnly; SameSite=Strict; Path=/; Secure",
                            )
                            .await;

                            ctx.append_response_metadata("new-access-token", &token)
                                .await;

                            let current_role_permissions =
                                fetch_current_role_permissions(db, sub_ref, &current_roles[0])
                                    .await?;

                            return Ok(AuthStatus {
                                is_auth: true,
                                sub: user_id,
                                current_role: current_roles[0].clone(),
                                new_access_token: Some(token),
                                current_role_permissions,
                            });
                        }
                        None => {
                            tracing::error!("User may not exist");
                            return Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"));
                        }
                    }
                }
                Err(err) => {
                    // Refresh token verification failed
                    tracing::error!("{}", err);
                    return Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"));
                }
            }
        }
        None => Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!")),
    }
}

/// A utility function to get a converted JWT secret key.
///
/// Make sure that the env vars are set before this function runs.
async fn get_converted_jwt_secret_key() -> Result<HS256Key, Error> {
    match env::var("JWT_SECRET_KEY") {
        Ok(secret_key) => Ok(HS256Key::from_bytes(secret_key.as_str().as_bytes())),
        Err(e) => {
            tracing::error!("{}", e);
            Err(Error::new(ErrorKind::Other, "Cannot proceed with request!"))
        }
    }
}

/// A utility function to verify user login credentials(username/email and password)
pub async fn verify_login_credentials<T: Clone + AsSurrealClient>(
    db: &T,
    raw_user_details: &UserLogins,
) -> Result<User, Error> {
    let user_details = raw_user_details.transformed();

    if user_details.user_name.is_none() || user_details.password.is_none() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "Invalid username or password",
        ));
    }

    let mut result = db
        .as_client()
        .query(
            "
        SELECT * FROM type::table($table) WHERE email = $login_id OR user_name = $login_id LIMIT 1
        ",
        )
        .bind(("table", "user"))
        .bind(("login_id", user_details.user_name.clone().unwrap()))
        .await
        .map_err(|e| {
            tracing::error!("{}", e);
            Error::new(ErrorKind::Other, "Database query failed")
        })?;

    // Get the first result from the first query
    let response: Option<User> = result.take(0).map_err(|e| {
        tracing::error!("{}", e);
        Error::new(ErrorKind::Other, "Database query deserialization failed")
    })?;

    match response {
        Some(user) => {
            let existing_password = user.password.clone();
            if existing_password.is_none() {
                tracing::error!("Cannot update password for user with no password");
                return Err(Error::new(ErrorKind::Other, "Invalid user details!"));
            }
            let existing_password = existing_password.unwrap();

            if bcrypt::verify(&user_details.password.unwrap(), &existing_password).map_err(|e| {
                tracing::error!("Failed to verify user credentials: {}", e);
                Error::new(ErrorKind::PermissionDenied, "Invalid username or password")
            })? && user.status == Some(AccountStatus::Active)
            {
                Ok(user)
            } else {
                Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "Invalid username or password",
                ))
            }
        }
        None => Err(Error::new(
            ErrorKind::PermissionDenied,
            "Invalid username or password",
        )),
    }
}

/// A utility function to sign JWTs
pub async fn sign_jwt(
    auth_claim: &AuthClaim,
    duration: Duration,
    user_id: &str,
) -> Result<String, Error> {
    let converted_key = get_converted_jwt_secret_key().await?;

    let mut token_claims = Claims::with_custom_claims(auth_claim.clone(), duration);
    token_claims.subject = Some(user_id.to_string());

    Ok(converted_key.authenticate(token_claims).map_err(|e| {
        tracing::error!("Failed to authenticate: {}", e);
        Error::new(ErrorKind::PermissionDenied, "Unauthorized!")
    })?)
}

pub async fn get_user_email<T: Clone + AsSurrealClient>(
    db: &T,
    user_id: &str,
) -> Result<String, Error> {
    let result: Option<User> = db
        .as_client()
        .select(("user", user_id))
        .await
        .map_err(|e| {
            tracing::error!("{}", e);
            Error::new(ErrorKind::Other, "Database query failed")
        })?;

    match result {
        Some(user) => Ok(user.email),
        None => Err(Error::new(
            ErrorKind::PermissionDenied,
            "Invalid username or password",
        )),
    }
}

/// A utility function to check a users' admin previleges
pub async fn confirm_authorization<T: Clone + AsSurrealClient>(
    db: &T,
    auth_status: &AuthStatus,
    auth_constraint: &AuthorizationConstraint,
) -> Result<bool, Error> {
    let formated_query = r#"
        LET $user = type::record('user', $user_id);
        LET $matching_roles = (
            SELECT ->assigned->(role WHERE
                (
                    role_name = $current_role_name
                    AND ->granted->permission.name CONTAINSALL $permission_constraints
                )) AS matching_roles
            FROM ONLY $user
        )['matching_roles'];
        IF $matching_roles != NONE
        AND array::len($matching_roles) > 0 {
            RETURN $matching_roles.map(
                |$matching_role: any| {
                    record::id($matching_role);
                }
            );
        } ELSE {
            RETURN [];
        };
    "#;

    let mut admin_privilege_check_query = db
        .as_client()
        .query(formated_query)
        .bind(("user_id", auth_status.sub.to_owned()))
        .bind(("current_role_name", auth_status.current_role.to_owned()))
        .bind((
            "permission_constraints",
            auth_constraint.permissions.to_vec(),
        ))
        .await
        .map_err(|e| {
            tracing::error!("{}", e);
            Error::new(ErrorKind::Other, "Database query failed")
        })?;

    // Get the first result from the first query
    let response: Vec<String> = admin_privilege_check_query.take(2).map_err(|e| {
        tracing::error!("admin_privilege_check_query: {}", e);
        Error::new(ErrorKind::Other, "Database query deserialization failed")
    })?;

    Ok(response.len() > 0)
}

/// A generic utility function to verify OAuth tokens for Google, GitHub, and other OAuth providers
pub async fn verify_oauth_token<T: for<'de> Deserialize<'de> + std::fmt::Debug>(
    oauth_client_name: OAuthClientName,
    token: &HeaderValue,
) -> Result<T, Error> {
    match oauth_client_name {
        OAuthClientName::Google => {
            let client = ReqWestClient::new();

            let mut req_headers = ReqWestHeaderMap::new();
            req_headers.insert("Authorization", token.to_owned());

            // make a request to google oauth server to verify the token
            let response =
                // reqwest::get(format!("https://oauth2.googleapis.com/people/me?access_token={}", token.to_str().unwrap().strip_prefix("Bearer ").unwrap()).as_str())
                client
                    .request(
                        Method::GET,
                        "https://www.googleapis.com/oauth2/v3/userinfo"
                    )
                    .headers(req_headers)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!("OAuth request to Google failed: {:?}", e);
                        Error::new(ErrorKind::Other, "OAuth request to Google failed")
                    })?;

            // Log the raw JSON response
            // let response_text = response.text().await.map_err(|e| {
            //     tracing::debug!("Failed to read response body: {:?}", e);
            //     Error::new(ErrorKind::Other, "Failed to read response body")
            // })?;
            // tracing::debug!("Raw response body: {}", response_text);

            // let user_data = serde_json::from_str::<T>(&response_text).map_err(|e| {
            //     tracing::debug!("Google Token deserialization failed: {:?}", e);
            //     Error::new(ErrorKind::Other, "Google Token deserialization failed")
            // })?;

            let user_data = response.json::<T>().await.map_err(|e| {
                tracing::error!("Google Token deserialization failed: {:?}", e);
                Error::new(ErrorKind::Other, "Google Token deserialization failed")
            })?;

            Ok(user_data)
        }
        OAuthClientName::Github => {
            // make a request to github oauth server to verify the token
            let client = ReqWestClient::new();

            let mut req_headers = ReqWestHeaderMap::new();
            req_headers.insert("Authorization", token.to_owned());

            req_headers.append(
                "Accept",
                "application/vnd.github+json".parse().map_err(|e| {
                    tracing::error!("Failed to parse headers: {}", e);
                    Error::new(ErrorKind::PermissionDenied, "Unauthorized!")
                })?,
            );

            req_headers.append(
                "X-GitHub-Api-Version",
                "2022-11-28".parse().map_err(|e| {
                    tracing::error!("Failed to parse headers: {}", e);
                    Error::new(ErrorKind::PermissionDenied, "Unauthorized!")
                })?,
            );

            let user_agent = env::var("GITHUB_OAUTH_USER_AGENT").map_err(|e| {
                tracing::error!(
                    "Missing the GITHUB_OAUTH_USER_AGENT environment variable.: {}",
                    e
                );
                Error::new(ErrorKind::PermissionDenied, "Server Error")
            })?;

            req_headers.append(
                "User-Agent",
                user_agent.as_str().parse().map_err(|e| {
                    tracing::error!("Failed to parse headers: {}", e);
                    Error::new(ErrorKind::PermissionDenied, "Unauthorized!")
                })?,
            );

            let response = client
                .request(Method::GET, "https://api.github.com/user")
                .headers(req_headers)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("OAuth request to GitHub failed: {:?}", e);
                    Error::new(ErrorKind::Other, "OAuth request to GitHub failed")
                })?;

            // let response_text = response.text().await.map_err(|e| {
            //     tracing::debug!("Failed to read response body: {:?}", e);
            //     Error::new(ErrorKind::Other, "Failed to read response body")
            // })?;
            // tracing::debug!("Rate limit response: {}", response_text);

            // let user_data = serde_json::from_str::<T>(&response_text).map_err(|e| {
            //     tracing::debug!("GitHub Token deserialization failed: {:?}", e);
            //     Error::new(ErrorKind::Other, "GitHub Token deserialization failed")
            // })?;

            let user_data = response.json::<T>().await.map_err(|e| {
                tracing::error!("GitHub Token deserialization failed: {}", e);
                Error::new(ErrorKind::Other, "GitHub Token deserialization failed")
            })?;

            Ok(user_data)
        }
    }
}

pub async fn create_oauth_user_if_not_exists<T: Clone + AsSurrealClient>(
    db: &T,
    oauth_client_name: OAuthClientName,
    user: &OAuthUser,
) -> Result<User, Error> {
    match oauth_client_name {
        OAuthClientName::Google => {
            if let OAuthUser::Google(google_user) = user {
                // Handle Google user
                let mut db_query = db
                    .as_client()
                    .query(
                        "
                        SELECT * FROM ONLY user WHERE oauth_user_id = $oauth_user_id LIMIT 1
                        ",
                    )
                    .bind(("oauth_user_id", google_user.sub.clone()))
                    .await
                    .map_err(|e| {
                        tracing::error!("DB Query Error: {}", e);
                        Error::new(ErrorKind::Other, "Internal Server error")
                    })?;

                let existing_user: Option<User> = db_query.take(0).map_err(|e| {
                    tracing::error!("Deserialization Error: {}", e);
                    Error::new(ErrorKind::Other, "Internal Server error")
                })?;

                match existing_user {
                    Some(existing_user) => Ok(existing_user),
                    None => {
                        let user = UserInput {
                            email: google_user.email.clone(),
                            oauth_client: Some(OAuthClientName::Google),
                            oauth_user_id: Some(google_user.sub.clone()),
                            status: AccountStatus::Active,
                            profile_picture: google_user.picture.clone(),
                            first_name: google_user.given_name.clone(),
                            last_name: google_user.family_name.clone(),
                            ..UserInput::default()
                        };

                        let created_user = create_user(db, user).await?;

                        match created_user {
                            Some(user) => Ok(user),
                            None => Err(Error::new(ErrorKind::Other, "Failed to create user!")),
                        }
                    }
                }
            } else {
                // Handle mismatch
                tracing::error!("Invalid Google OAuth user!");
                Err(Error::new(ErrorKind::Other, "Invalid Google OAuth user!"))
            }
        }
        OAuthClientName::Github => {
            if let OAuthUser::Github(github_user) = user {
                // Handle Github user
                let mut db_query = db
                    .as_client()
                    .query(
                        "
                        SELECT * FROM ONLY user WHERE oauth_user_id = type::string($oauth_user_id) LIMIT 1
                        ",
                    )
                    .bind(("oauth_user_id", github_user.id.clone()))
                    .await
                    .map_err(|e| {
                        tracing::error!("DB Query Error: {}", e);
                        Error::new(ErrorKind::Other, "Internal Server error")
                    })?;

                let existing_user: Option<User> = db_query.take(0).map_err(|e| {
                    tracing::error!("Deserialization Error: {}", e);
                    Error::new(ErrorKind::Other, "Internal Server error")
                })?;

                match existing_user {
                    Some(existing_user) => Ok(existing_user),
                    None => {
                        let email = github_user.email.as_ref();

                        if email.is_none() {
                            tracing::error!("No primary email found");
                            return Err(Error::new(ErrorKind::Other, "No primary email found on your GitHub account. Please go to GitHub Settings → Emails and set a primary email, then try again."));
                        }

                        let mut name_parts =
                            github_user.name.as_deref().unwrap_or("").splitn(2, ' ');

                        let first_name = name_parts
                            .next()
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned);
                        let last_name = name_parts
                            .next()
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned);

                        let user = UserInput {
                            email: email.unwrap().to_owned(),
                            oauth_client: Some(OAuthClientName::Github),
                            oauth_user_id: Some(github_user.id.to_string()),
                            status: AccountStatus::Active,
                            profile_picture: Some(github_user.avatar_url.clone()),
                            first_name,
                            last_name,
                            ..UserInput::default()
                        };

                        let created_user = create_user(db, user).await?;

                        match created_user {
                            Some(user) => Ok(user),
                            None => Err(Error::new(ErrorKind::Other, "Failed to create user!")),
                        }
                    }
                }
            } else {
                // Handle mismatch
                tracing::error!("Invalid Github OAuth user!");
                Err(Error::new(ErrorKind::Other, "Invalid GitHub OAuth user!"))
            }
        }
    }
}

pub async fn fetch_user_roles<T: Clone + AsSurrealClient>(
    db: &T,
    user_id: &str,
    role_id: Option<&str>,
) -> Result<Vec<String>, Error> {
    let owned_user_id = user_id.to_string();
    let owned_role_id = role_id.unwrap_or("").to_owned();

    let mut user_roles_res = db
        .as_client()
        .query(
            "
            LET $user = type::record('user', $user_id);

            (SELECT ->(assigned WHERE is_default=true)->role.* AS roles FROM ONLY user WHERE id = $user LIMIT 1)['roles'];

            LET $role = type::record('role', $role_id);
            LET $user = type::record('user', $user_id);

            (SELECT ->assigned->(role WHERE id = $role)[*] AS roles FROM ONLY user WHERE id = $user LIMIT 1)['roles'];
            "
        )
        .bind(("user_id", owned_user_id))
        .bind(("role_id", owned_role_id))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get roles: {}", e);
            Error::new(ErrorKind::Other, "DB Query failed: Get Roles")
        })?;
    let user_roles: Vec<String> = match role_id {
        Some(_) => user_roles_res.take((4, "role_name")).map_err(|e| {
            tracing::error!("Failed to deserialize roles(take(1)): {}", e);
            Error::new(ErrorKind::Other, "Failed to fetch roles")
        })?,
        None => user_roles_res.take((1, "role_name")).map_err(|e| {
            tracing::error!("Failed to deserialize roles(take(0)): {}", e);
            Error::new(ErrorKind::Other, "Failed to fetch roles")
        })?,
    };

    Ok(user_roles)
}

async fn refresh_oauth_access_token(
    oauth_client_name: OAuthClientName,
    refresh_token: &str,
) -> Result<OAuthTokenPair, Error> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build HTTP client: {}", e);
            Error::new(ErrorKind::Other, "Internal error")
        })?;

    let oauth_client = initiate_auth_code_grant_flow(oauth_client_name)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initiate auth code grant flow: {}", e);
            Error::new(ErrorKind::Other, "Internal error")
        })?;

    let token_result = oauth_client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
        .request_async(&http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to refresh OAuth token: {:?}", e);
            Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
        })?;

    Ok(OAuthTokenPair {
        access_token: token_result.access_token().secret().to_owned(),
        refresh_token: token_result.refresh_token().map(|t| t.secret().to_owned()),
    })
}

async fn handle_oauth_refresh_token<T, C>(
    cookies: &HashMap<String, String>,
    db: &T,
    ctx: &C,
) -> Result<AuthStatus, Error>
where
    T: Clone + AsSurrealClient,
    C: AuthMetadataContext + Sync,
{
    let refresh_token = cookies.get("t").ok_or_else(|| {
        tracing::error!("Missing OAuth refresh token cookie");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    let oauth_client_name = cookies.get("oauth_client").ok_or_else(|| {
        tracing::error!("Missing oauth_client cookie");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    let oauth_user_roles_jwt = cookies.get("oauth_user_roles_jwt").ok_or_else(|| {
        tracing::error!("Missing oauth_user_roles_jwt cookie");
        Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
    })?;

    // Decode the roles JWT to get claims (ignore expiry — access token expired, not this)
    let converted_jwt_secret_key = get_converted_jwt_secret_key().await?;
    let role_claims = converted_jwt_secret_key
        .verify_token::<AuthClaim>(oauth_user_roles_jwt, None)
        .map_err(|e| {
            tracing::error!("Failed to decode oauth_user_roles_jwt: {}", e);
            Error::new(ErrorKind::PermissionDenied, "Not Authorized!")
        })?;

    // Exchange refresh token for new access token (and possibly new refresh token)
    let token_pair =
        refresh_oauth_access_token(OAuthClientName::from_str(oauth_client_name), refresh_token)
            .await?;

    // Rotate the refresh token cookie — GitHub Apps always returns a new one
    if let Some(new_refresh_token) = &token_pair.refresh_token {
        ctx.set_response_metadata(
            "set-cookie",
            &format!(
                "t={}; HttpOnly; SameSite=Strict; Path=/; Secure",
                new_refresh_token
            ),
        )
        .await;
    }

    let token_header = HeaderValue::from_str(&format!("Bearer {}", token_pair.access_token))
        .map_err(|e| {
            tracing::error!("Failed to create token header: {}", e);
            Error::new(ErrorKind::Other, "Unauthorized!")
        })?;

    // Verify the new access token with the provider and get sub
    let sub = match OAuthClientName::from_str(oauth_client_name) {
        OAuthClientName::Google => {
            let user = verify_oauth_token::<GoogleUserInfo>(OAuthClientName::Google, &token_header)
                .await?;
            user.sub
        }
        OAuthClientName::Github => {
            let user =
                verify_oauth_token::<GithubUserProfile>(OAuthClientName::Github, &token_header)
                    .await?;
            user.id.to_string()
        }
    };

    // Send the new access token back to the client
    ctx.append_response_metadata("new-access-token", &token_pair.access_token)
        .await;
    let current_role_id = role_claims.custom.roles[0].clone();

    let current_role_permissions =
        fetch_current_role_permissions(db, &sub, &current_role_id).await?;

    Ok(AuthStatus {
        is_auth: true,
        sub,
        current_role: current_role_id,
        new_access_token: Some(token_pair.access_token),
        current_role_permissions,
    })
}

pub async fn fetch_current_role_permissions<T: Clone + AsSurrealClient>(
    db: &T,
    user_id: &str,
    role_name: &str,
) -> Result<Vec<String>, Error> {
    let owned_user_id = user_id.to_owned();
    let owned_role_name = role_name.to_owned();

    let mut query_response = db
        .as_client()
        // Apparently SurrealDB formats the query string before executing it. It may result in unexpected behavior.
        .query(
            "
            LET $role = (SELECT VALUE id FROM ONLY role WHERE role_name = $role_name LIMIT 1);
            LET $user = type::record('user', $user_id);


            LET $permissions = (SELECT ->assigned->(role WHERE id = $role)->granted->permission[*] AS permissions FROM ONLY user WHERE id = $user OR oauth_user_id = $user_id LIMIT 1)['permissions'];
            RETURN $permissions;
            "
        )
        .bind(("user_id", owned_user_id))
        .bind(("role_name", owned_role_name))
        .await
        .map_err(|e| {
            tracing::error!("DB Query failed. Failed to get role permissions: {}", e);
            Error::new(ErrorKind::Other, "Failed to fetch permissions")
        })?;
    let user_role_permissions: Vec<String> = query_response.take((3, "name")).map_err(|e| {
        tracing::error!("Failed to deserialize permissions(take(0)): {}", e);
        Error::new(ErrorKind::Other, "Failed to fetch permissions")
    })?;

    Ok(user_role_permissions)
}
