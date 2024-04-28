use axum::{http::HeaderValue, Extension};
use jwt_simple::prelude::*;
use lib::utils::{
    auth::{AuthClaim, SymKey},
    custom_error::ExtendedError,
};
use std::time::Duration;
use std::{env, sync::Arc};
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use async_graphql::{Context, Enum, Result};
use dotenvy::dotenv;
use hyper::header::SET_COOKIE;
use oauth2::basic::{BasicClient, BasicErrorResponseType, BasicTokenType};

use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge,
    RedirectUrl, RevocationErrorResponseType, RevocationUrl, Scope, StandardErrorResponse,
    StandardRevocableToken, StandardTokenIntrospectionResponse, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

// use crate::SharedState;

pub type OAuthClientInstance = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    BasicTokenType,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
>;

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum OAuthFlow {
    AuthCodeGrant,
    ClientCredentials,
    ResourceOwnerPassword,
    DeviceCode,
    RefreshToken,
}

#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum OAuthClientName {
    Google,
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

pub async fn initiate_auth_code_grant_flow(oauth_client: OAuthClientName) -> OAuthClientInstance {
    dotenv().ok();
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = match oauth_client {
        OAuthClientName::Google => BasicClient::new(
            ClientId::new(
                env::var("GOOGLE_OAUTH_CLIENT_ID")
                    .expect("Missing the GOOGLE_OAUTH_CLIENT_ID environment variable."),
            ),
            Some(ClientSecret::new(
                env::var("GOOGLE_OAUTH_CLIENT_SECRET")
                    .expect("Missing the GOOGLE_OAUTH_CLIENT_SECRET environment variable."),
            )),
            AuthUrl::new(
                env::var("GOOGLE_OAUTH_AUTHORIZE_URL")
                    .expect("Missing the GOOGLE_OAUTH_AUTHORIZE_URL environment variable."),
            )
            .unwrap(),
            Some(
                TokenUrl::new(
                    env::var("GOOGLE_OAUTH_ACCESS_TOKEN_URL")
                        .expect("Missing the GOOGLE_OAUTH_ACCESS_TOKEN_URL environment variable."),
                )
                .unwrap(),
            ),
        )
        .set_revocation_uri(
            RevocationUrl::new(
                env::var("GOOGLE_OAUTH_REVOKE_TOKEN_URL")
                    .expect("Missing the GOOGLE_OAUTH_REVOKE_TOKEN_URL environment variable."),
            )
            .expect("Invalid revocation endpoint URL"),
        ),
        OAuthClientName::Github => BasicClient::new(
            ClientId::new(
                env::var("GITHUB_OAUTH_CLIENT_ID")
                    .expect("Missing the GITHUB_OAUTH_CLIENT_ID environment variable."),
            ),
            Some(ClientSecret::new(
                env::var("GITHUB_OAUTH_CLIENT_SECRET")
                    .expect("Missing the GITHUB_OAUTH_CLIENT_SECRET environment variable."),
            )),
            AuthUrl::new(
                env::var("GITHUB_OAUTH_AUTHORIZE_URL")
                    .expect("Missing the GITHUB_OAUTH_AUTHORIZE_URL environment variable."),
            )
            .unwrap(),
            Some(
                TokenUrl::new(
                    env::var("GITHUB_OAUTH_ACCESS_TOKEN_URL")
                        .expect("Missing the GITHUB_OAUTH_ACCESS_TOKEN_URL environment variable."),
                )
                .unwrap(),
            ),
        ),
    };

    client.set_redirect_uri(
        RedirectUrl::new(
            env::var("OAUTH_REDIRECT_URI")
                .expect("Missing the OAUTH_REDIRECT_URI environment variable."),
        )
        .unwrap(),
    )
}

pub async fn navigate_to_redirect_url(
    oauth_client: OAuthClientInstance,
    ctx: &Context<'_>,
    oauth_client_name: OAuthClientName,
) -> String {
    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let auth_request = match oauth_client_name {
        OAuthClientName::Google => {
            oauth_client
                .authorize_url(CsrfToken::new_random)
                // Set the desired scopes.
                .add_scope(Scope::new(
                    "https://www.googleapis.com/auth/plus.me".to_string(),
                ))
        }
        OAuthClientName::Github => {
            oauth_client
                .authorize_url(CsrfToken::new_random)
                // Set the desired scopes.
                .add_scope(Scope::new("read".to_string()))
                .add_scope(Scope::new("write".to_string()))
                .add_scope(Scope::new("user".to_string()))
        }
    };

    let (auth_url, csrf_token) = auth_request
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Browse to: {}", auth_url);

    // Insert the csrf_state, oauth_client, pkce_verifier cookies
    // TODO: Add back these on HTTPS? <cookie_name>={}; HttpOnly; SameSite=Strict;
    ctx.insert_http_header(
        SET_COOKIE,
        format!("oauth_client={}", oauth_client_name.fmt()),
    );

    let sensitive_cookies_expiry_duration = Duration::from_secs(120); // limit the duration of the sensitive cookies
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "j={}; Max-Age={}",
            csrf_token.secret(),
            sensitive_cookies_expiry_duration.as_secs()
        ),
    );
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "k={}; Max-Age={}",
            pkce_verifier.secret(),
            sensitive_cookies_expiry_duration.as_secs()
        ),
    );

    auth_url.to_string()
}

pub async fn decode_token(
    ctx: &Context<'_>,
    token_header: &HeaderValue,
) -> Result<JWTClaims<AuthClaim>> {
    let token = token_header.to_str().unwrap().strip_prefix("Bearer ");

    match token {
        Some(token) => {
            println!("token: {:?}", token);
            let key: Vec<u8>;

            let db = ctx
                .data::<Extension<Arc<Surreal<SurrealClient>>>>()
                .unwrap();
            let mut result = db
                .query("SELECT * FROM type::table($table) WHERE name = 'jwt_key' LIMIT 1")
                .bind(("table", "crypto_key"))
                .await?;
            let response: Option<SymKey> = result.take(0)?;

            match &response {
                Some(key_container) => {
                    println!("key_container: {:?}", key_container.key.clone());
                    key = key_container.key.clone();
                }
                None => {
                    // key = HS256Key::generate().to_bytes();
                    return Err(
                        ExtendedError::new("Not Authorized!", Some(403.to_string())).build()
                    );
                }
            }

            let converted_key = HS256Key::from_bytes(&key);

            let _claims = converted_key.verify_token::<AuthClaim>(&token, None);

            println!("claims: {:?}", _claims);

            match &_claims {
                Ok(_) => {
                    // let sub = _claims
                    //     .as_ref()
                    //     .unwrap()
                    //     .subject
                    //     .as_ref()
                    //     .map(|t| t.to_string())
                    //     .unwrap_or("".to_string());
                    // let is_auth = true;
                    // Ok(AuthStatus {
                    //     is_auth,
                    //     sub: sub.to_string(),
                    // })
                    Ok(_claims.unwrap())
                }
                Err(e) => Err(ExtendedError::new(e.to_string(), Some(403.to_string())).build()),
            }
        }
        None => Err(
            ExtendedError::new("Invalid token format".to_string(), Some(403.to_string())).build(),
        ),
    }
}
