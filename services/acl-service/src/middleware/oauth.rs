use axum::{http::HeaderValue, Extension};
use jwt_simple::prelude::*;
use lib::utils::{
    auth::{AuthClaim, AuthStatus, SymKey}, cookie_parser::parse_cookies, custom_error::ExtendedError
};
use std::time::Duration;
use std::{env, sync::Arc};
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use async_graphql::{Context, Enum, Result};
use dotenvy::dotenv;
use hyper::{header::{COOKIE, SET_COOKIE}, HeaderMap, Method};
use oauth2::basic::{BasicClient, BasicErrorResponseType, BasicTokenType};
use reqwest::{header::HeaderMap as ReqWestHeaderMap, Client as ReqWestClient};

use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge,
    RedirectUrl, RevocationErrorResponseType, RevocationUrl, Scope, StandardErrorResponse,
    StandardRevocableToken, StandardTokenIntrospectionResponse, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::graphql::schemas::{role::SystemRole, user::{DecodedGithubOAuthToken, DecodedGoogleOAuthToken, SurrealRelationQueryResponse, User}};

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

            match &_claims {
                Ok(_) => {
                    // Token verification successful
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

pub async fn get_user_id_from_token(ctx: &Context<'_>) -> Result<String> {
    match ctx.data_opt::<HeaderMap>() {
        Some(headers) => {
            let token_claims = decode_token(ctx, headers.get("Authorization").unwrap()).await;

            match token_claims {
                Ok(token_claims) => Ok(token_claims.subject.unwrap()),
                Err(e) => Err(e),
            }
        }
        None => {
            Err(ExtendedError::new("No headers found".to_string(), Some(403.to_string())).build())
        }
    }
}

pub async fn confirm_auth(ctx: &Context<'_>) -> Result<AuthStatus> {
    // Process request headers as needed
    match ctx.data_opt::<HeaderMap>() {
        Some(headers) => {
            // Check if Authorization header is present
            match headers.get("Authorization") {
                Some(token) => {
                    // Check if Cookie header is present
                    match headers.get(COOKIE) {
                        Some(cookie_header) => {
                            let cookies_str = cookie_header
                                .to_str()
                                .map_err(|_| "Invalid cookie format")?;
                            let cookies = parse_cookies(cookies_str);

                            // Check if oauth_client cookie is present
                            match cookies.get("oauth_client") {
                                Some(oauth_client) => {
                                    if oauth_client.is_empty() {
                                        let key: Vec<u8>;
                                        let db =
                                            ctx.data::<Extension<Arc<Surreal<SurrealClient>>>>().unwrap();
                                        let mut result = db.query("SELECT * FROM type::table($table) WHERE name = 'jwt_key' LIMIT 1")
                                                .bind(("table", "crypto_key"))
                                                .await?;
                                        let response: Option<SymKey> = result.take(0)?;

                                        match &response {
                                            Some(key_container) => {
                                                key = key_container.key.clone();
                                            }
                                            None => {
                                                // key = HS256Key::generate().to_bytes();
                                                return Err(ExtendedError::new(
                                                    "Not Authorized!",
                                                    Some(403.to_string()),
                                                )
                                                .build());
                                            }
                                        }

                                        let converted_key = HS256Key::from_bytes(&key);

                                        let token_claims = decode_token(ctx, token).await;

                                        match &token_claims {
                                            Ok(_) => {
                                                // Token verification successful
                                                return Ok(AuthStatus {
                                                    is_auth: true,
                                                    sub: token_claims
                                                        .as_ref()
                                                        .unwrap()
                                                        .subject
                                                        .as_ref()
                                                        .map(|t| t.to_string())
                                                        .unwrap_or("".to_string()),
                                                });
                                            }
                                            Err(_err) => {
                                                // Token verification failed, check if refresh token is present
                                                match cookies.get("t") {
                                                    Some(refresh_token) => {
                                                        let refresh_claims = converted_key
                                                            .verify_token::<AuthClaim>(
                                                                &refresh_token,
                                                                None,
                                                            );

                                                        match refresh_claims {
                                                            Ok(refresh_claims) => {
                                                                // TODO: Refresh token verification successful, issue new access token
                                                                // call sign_in mutation
                                                                let user: Option<User> = db
                                                                    .select((
                                                                        "user",
                                                                        refresh_claims
                                                                            .subject
                                                                            .unwrap()
                                                                            .as_str(),
                                                                    ))
                                                                    .await?;

                                                                match user {
                                                                    Some(user) => {
                                                                        let get_user_roles_query = format!(
                                                                            "SELECT ->has_role.out.* FROM user:{}",
                                                                            user.id.as_ref().map(|t| &t.id).expect("id")
                                                                        );
                                                                        let mut user_roles_res = db.query(get_user_roles_query).await?;
                                                                        let user_roles: Option<SurrealRelationQueryResponse<SystemRole>> =
                                                                            user_roles_res.take(0)?;
                                                                        // println!("user_roles: {:?}", user_roles);

                                                                        let auth_claim =
                                                                            AuthClaim {
                                                                                roles:
                                                                                    match user_roles
                                                                                    {
                                                                                        Some(
                                                                                            existing_roles,
                                                                                        ) => {
                                                                                            // use id instead of Thing
                                                                                            existing_roles
                                                                                        .get("->has_role")
                                                                                        .unwrap()
                                                                                        .get("out")
                                                                                        .unwrap()
                                                                                        // existing_roles["->has_role"]["out"]
                                                                                        .into_iter()
                                                                                        .map(|role| {
                                                                                            role.id
                                                                                                .as_ref()
                                                                                                .map(|t| &t.id)
                                                                                                .expect("id")
                                                                                                .to_raw()
                                                                                        })
                                                                                        .collect()
                                                                                        }
                                                                                        None => {
                                                                                            vec![]
                                                                                        }
                                                                                    },
                                                                            };

                                                                        let mut token_claims = Claims::with_custom_claims(auth_claim.clone(), Duration::from_secs(15 * 60).into());
                                                                        token_claims.subject = Some(
                                                                            user.id
                                                                                .as_ref()
                                                                                .map(|t| &t.id)
                                                                                .expect("id")
                                                                                .to_raw(),
                                                                        );

                                                                        let token = converted_key
                                                                            .authenticate(
                                                                                token_claims,
                                                                            )
                                                                            .unwrap();

                                                                        ctx.insert_http_header(
                                                                            SET_COOKIE,
                                                                            format!(
                                                                                "oauth_client="
                                                                            ),
                                                                        );

                                                                        ctx.append_http_header(
                                                                            "New-Access-Token",
                                                                            format!(
                                                                                "Bearer {}",
                                                                                token
                                                                            ),
                                                                        );

                                                                        return Ok(AuthStatus {
                                                                            is_auth: true,
                                                                            sub: user
                                                                                .id
                                                                                .as_ref()
                                                                                .map(|t| &t.id)
                                                                                .expect("id")
                                                                                .to_raw(),
                                                                        });
                                                                    }
                                                                    None => {
                                                                        return Err(
                                                                            ExtendedError::new(
                                                                                "Not Authorized!",
                                                                                Some(
                                                                                    403.to_string(),
                                                                                ),
                                                                            )
                                                                            .build(),
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                            Err(_err) => {
                                                                // Refresh token verification failed
                                                                return Err(ExtendedError::new(
                                                                    "Not Authorized!",
                                                                    Some(403.to_string()),
                                                                )
                                                                .build());
                                                            }
                                                        }
                                                    }
                                                    None => Err(ExtendedError::new(
                                                        "Not Authorized!",
                                                        Some(403.to_string()),
                                                    )
                                                    .build()),
                                                }
                                            }
                                        }
                                    } else {
                                        let oauth_client_name =
                                            OAuthClientName::from_str(oauth_client);

                                        match oauth_client_name {
                                            OAuthClientName::Google => {
                                                // make a request to google oauth server to verify the token
                                                let response =
                                                    reqwest::get(format!("https://oauth2.googleapis.com/tokeninfo?access_token={}", token.to_str().unwrap().strip_prefix("Bearer ").unwrap()).as_str())
                                                        .await?
                                                        .json::<DecodedGoogleOAuthToken>()
                                                        .await?;

                                                return Ok(AuthStatus {
                                                    is_auth: true,
                                                    sub: response.sub,
                                                });
                                            }
                                            OAuthClientName::Github => {
                                                // make a request to github oauth server to verify the token
                                                let client = ReqWestClient::new();

                                                let mut req_headers = ReqWestHeaderMap::new();
                                                req_headers
                                                    .insert("Authorization", token.to_owned());

                                                req_headers.append(
                                                    "Accept",
                                                    "application/vnd.github+json".parse().unwrap(),
                                                );

                                                req_headers.append(
                                                    "X-GitHub-Api-Version",
                                                    "2022-11-28".parse().unwrap(),
                                                );


                                                let response = client
                                                    .request(
                                                        Method::GET,
                                                        "https://api.github.com/user",
                                                    )
                                                    // .get("https://api.github.com/user")
                                                    .headers(req_headers)
                                                    .send()
                                                    .await?
                                                    .json::<DecodedGithubOAuthToken>()
                                                    .await?;


                                                return Ok(AuthStatus {
                                                    is_auth: true,
                                                    sub: response.id.to_string(),
                                                });
                                            }
                                        }
                                    }
                                }
                                None => Err(ExtendedError::new(
                                    "Not Authorized!",
                                    Some(403.to_string()),
                                )
                                .build()),
                            }
                        }
                        None => {
                            Err(ExtendedError::new("Not Authorized!", Some(403.to_string()))
                                .build())
                        }
                    }
                }
                None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
            }
        }
        None => Err(ExtendedError::new("Invalid request!", Some(400.to_string())).build()),
    }
}
