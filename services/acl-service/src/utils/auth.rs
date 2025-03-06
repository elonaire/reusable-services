use axum::{http::HeaderValue, Extension};
use jwt_simple::prelude::*;
use lib::utils::{
    auth::{AuthClaim, SymKey},
    cookie_parser::parse_cookies,
    models::AuthStatus,
};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    // time::Duration,
};
use std::{env, sync::Arc};
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use async_graphql::{Context, Enum};
use dotenvy::dotenv;
use hyper::{
    header::{COOKIE, SET_COOKIE},
    HeaderMap, Method,
};
use oauth2::{
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
    EndpointNotSet, EndpointSet,
};
use reqwest::{header::HeaderMap as ReqWestHeaderMap, Client as ReqWestClient};

use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge,
    RedirectUrl, RevocationErrorResponseType, RevocationUrl, Scope, StandardErrorResponse,
    StandardRevocableToken, StandardTokenIntrospectionResponse, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::graphql::schemas::{
    role::SystemRole,
    user::{
        AccountStatus, DecodedGithubOAuthToken, DecodedGoogleOAuthToken,
        SurrealRelationQueryResponse, User, UserLogins,
    },
};

// use crate::SharedState;

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

// Define a trait to get the Surreal<Client>
pub trait AsSurrealClient {
    fn as_client(&self) -> &Surreal<SurrealClient>;
}

// Implement for Arc<Surreal<Client>>
impl AsSurrealClient for Arc<Surreal<SurrealClient>> {
    fn as_client(&self) -> &Surreal<SurrealClient> {
        self.as_ref()
    }
}

// Implement for Extension<Arc<Surreal<Client>>>
impl AsSurrealClient for Extension<Arc<Surreal<SurrealClient>>> {
    fn as_client(&self) -> &Surreal<SurrealClient> {
        self.0.as_ref()
    }
}

/// Creates a desired OAuthClient of choice. For now GitHub and Google
pub async fn initiate_auth_code_grant_flow(oauth_client: OAuthClientName) -> OAuthClientInstance {
    dotenv().ok();
    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = match oauth_client {
        OAuthClientName::Google => BasicClient::new(ClientId::new(
            env::var("GOOGLE_OAUTH_CLIENT_ID")
                .expect("Missing the GOOGLE_OAUTH_CLIENT_ID environment variable."),
        ))
        .set_client_secret(ClientSecret::new(
            env::var("GOOGLE_OAUTH_CLIENT_SECRET")
                .expect("Missing the GOOGLE_OAUTH_CLIENT_SECRET environment variable."),
        ))
        .set_auth_uri(
            AuthUrl::new(
                env::var("GOOGLE_OAUTH_AUTHORIZE_URL")
                    .expect("Missing the GOOGLE_OAUTH_AUTHORIZE_URL environment variable."),
            )
            .unwrap(),
        )
        .set_token_uri(
            TokenUrl::new(
                env::var("GOOGLE_OAUTH_ACCESS_TOKEN_URL")
                    .expect("Missing the GOOGLE_OAUTH_ACCESS_TOKEN_URL environment variable."),
            )
            .unwrap(),
        )
        .set_revocation_url(
            RevocationUrl::new(
                env::var("GOOGLE_OAUTH_REVOKE_TOKEN_URL")
                    .expect("Missing the GOOGLE_OAUTH_REVOKE_TOKEN_URL environment variable."),
            )
            .expect("Invalid revocation endpoint URL"),
        ),
        OAuthClientName::Github => BasicClient::new(ClientId::new(
            env::var("GITHUB_OAUTH_CLIENT_ID")
                .expect("Missing the GITHUB_OAUTH_CLIENT_ID environment variable."),
        ))
        .set_client_secret(ClientSecret::new(
            env::var("GITHUB_OAUTH_CLIENT_SECRET")
                .expect("Missing the GITHUB_OAUTH_CLIENT_SECRET environment variable."),
        ))
        .set_auth_uri(
            AuthUrl::new(
                env::var("GITHUB_OAUTH_AUTHORIZE_URL")
                    .expect("Missing the GITHUB_OAUTH_AUTHORIZE_URL environment variable."),
            )
            .unwrap(),
        )
        .set_token_uri(
            TokenUrl::new(
                env::var("GITHUB_OAUTH_ACCESS_TOKEN_URL")
                    .expect("Missing the GITHUB_OAUTH_ACCESS_TOKEN_URL environment variable."),
            )
            .unwrap(),
        )
        .set_revocation_url(RevocationUrl::new("".to_string()).unwrap()),
    };

    client.set_redirect_uri(
        RedirectUrl::new(
            env::var("OAUTH_REDIRECT_URI")
                .expect("Missing the OAUTH_REDIRECT_URI environment variable."),
        )
        .unwrap(),
    )
}

// Generates a Redirect url for the OAuth Code Grant Flow
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
    ctx.insert_http_header(
        SET_COOKIE,
        format!(
            "oauth_client={}; HttpOnly; SameSite=Strict",
            oauth_client_name.fmt()
        ),
    );

    let sensitive_cookies_expiry_duration = Duration::from_secs(120); // limit the duration of the sensitive cookies
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "j={}; Max-Age={}; HttpOnly; SameSite=Strict",
            csrf_token.secret(),
            sensitive_cookies_expiry_duration.as_secs()
        ),
    );
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "k={}; Max-Age={}; HttpOnly; SameSite=Strict",
            pkce_verifier.secret(),
            sensitive_cookies_expiry_duration.as_secs()
        ),
    );

    auth_url.to_string()
}

/// A utility function to decode JWT tokens. Returns full claims
pub async fn decode_token<T: Clone + AsSurrealClient>(
    db: &T,
    token_header: &HeaderValue,
) -> Result<JWTClaims<AuthClaim>, Error> {
    let token = token_header.to_str().unwrap().strip_prefix("Bearer ");

    match token {
        Some(token) => {
            let converted_jwt_secret_key = get_converted_jwt_secret_key(db)
                .await
                .map_err(|_e| Error::new(ErrorKind::PermissionDenied, "Jwt Key failed"))?;

            let claims_result = converted_jwt_secret_key.verify_token::<AuthClaim>(&token, None);

            match claims_result {
                Ok(claims) => {
                    // Token verification successful
                    Ok(claims)
                }
                Err(e) => Err(Error::new(ErrorKind::Other, e.to_string().as_str())),
            }
        }
        None => Err(Error::new(ErrorKind::Other, "Invalid token format")),
    }
}

/// A utility function to decode JWT tokens. Returns only the user id
pub async fn get_user_id_from_token(ctx: &Context<'_>) -> Result<String, Error> {
    match ctx.data_opt::<HeaderMap>() {
        Some(headers) => {
            let db = ctx
                .data::<Extension<Arc<Surreal<SurrealClient>>>>()
                .unwrap();

            let token_claims = decode_token(db, headers.get("Authorization").unwrap()).await;

            match token_claims {
                Ok(token_claims) => Ok(token_claims.subject.unwrap()),
                Err(e) => Err(e),
            }
        }
        None => Err(Error::new(ErrorKind::Other, "No headers found")),
    }
}

/// A utility function to confirm auth by parsing relevant headers. Useful for authenticating clients. Includes refresh token handling and OAuth
pub async fn confirm_auth(ctx: &Context<'_>) -> Result<AuthStatus, Error> {
    // Process request headers as needed
    match ctx.data_opt::<HeaderMap>() {
        Some(headers) => {
            // Check if Authorization header is present
            match headers.get("Authorization") {
                Some(token) => {
                    // Check if Cookie header is present
                    match headers.get(COOKIE) {
                        Some(cookie_header) => {
                            let cookies_str = cookie_header.to_str().map_err(|_| {
                                Error::new(ErrorKind::InvalidData, "Invalid cookie format")
                            })?;
                            let cookies = parse_cookies(cookies_str);

                            // Check if oauth_client cookie is present
                            match cookies.get("oauth_client") {
                                Some(oauth_client) => {
                                    if oauth_client.is_empty() {
                                        let db = ctx
                                            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
                                            .unwrap();

                                        let token_claims = decode_token(db, token).await;

                                        match &token_claims {
                                            Ok(claims) => {
                                                // Token verification successful
                                                Ok(AuthStatus {
                                                    is_auth: true,
                                                    sub: claims
                                                        .subject
                                                        .as_ref()
                                                        .map(|t| t.to_string())
                                                        .unwrap_or("".to_string()),
                                                })
                                            }
                                            Err(_err) => {
                                                // Token verification failed, check if refresh token is present
                                                let converted_jwt_secret_key =
                                                    get_converted_jwt_secret_key(db)
                                                        .await
                                                        .map_err(|_e| {
                                                            Error::new(
                                                                ErrorKind::PermissionDenied,
                                                                "Jwt Key failed",
                                                            )
                                                        })?;

                                                handle_refresh_token(
                                                    &cookies,
                                                    &converted_jwt_secret_key,
                                                    ctx,
                                                )
                                                .await
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
                                                        .await
                                                        .map_err(|_e| {
                                                            Error::new(ErrorKind::Other, "OAuth request to Google failed")
                                                        })?
                                                        .json::<DecodedGoogleOAuthToken>()
                                                        .await
                                                        .map_err(|_e| {
                                                            Error::new(ErrorKind::Other, "Google Token deserialization failed")
                                                        })?;

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
                                                    .headers(req_headers)
                                                    .send()
                                                    .await
                                                    .map_err(|_e| {
                                                        Error::new(
                                                            ErrorKind::Other,
                                                            "OAuth request to GitHub failed",
                                                        )
                                                    })?
                                                    .json::<DecodedGithubOAuthToken>()
                                                    .await
                                                    .map_err(|_e| {
                                                        Error::new(
                                                            ErrorKind::Other,
                                                            "GitHub Token deserialization failed",
                                                        )
                                                    })?;

                                                return Ok(AuthStatus {
                                                    is_auth: true,
                                                    sub: response.id.to_string(),
                                                });
                                            }
                                        }
                                    }
                                }
                                None => {
                                    Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"))
                                }
                            }
                        }
                        None => Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!")),
                    }
                }
                None => Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!")),
            }
        }
        None => Err(Error::new(ErrorKind::Other, "Invalid request!")),
    }
}

/// A utility function to handle refresh tokens
async fn handle_refresh_token(
    cookies: &HashMap<String, String>,
    converted_jwt_secret_key: &HS256Key,
    ctx: &Context<'_>,
) -> Result<AuthStatus, Error> {
    match cookies.get("t") {
        Some(refresh_token) => {
            let refresh_claims =
                converted_jwt_secret_key.verify_token::<AuthClaim>(&refresh_token, None);

            match refresh_claims {
                Ok(refresh_claims) => {
                    let db = ctx
                        .data::<Extension<Arc<Surreal<SurrealClient>>>>()
                        .unwrap();

                    let user: Option<User> = db
                        .select(("user", refresh_claims.subject.unwrap().as_str()))
                        .await
                        .map_err(|_e| {
                            Error::new(ErrorKind::Other, "User deserialization failed")
                        })?;

                    match user {
                        Some(user) => {
                            let mut user_roles_res = db
                                .query("
                                    SELECT ->has_role->role.* AS roles FROM ONLY type::thing($user_id)
                                    ")
                                .bind(("user_id", format!(
                                    "user:{}",
                                    user.id.as_ref().map(|t| &t.id).expect("id")
                                )))
                                .await
                                .map_err(|_e| Error::new(ErrorKind::Other, "DB Query failed"))?;
                            let user_roles: Option<SurrealRelationQueryResponse<SystemRole>> =
                                user_roles_res.take(0).map_err(|_e| {
                                    Error::new(ErrorKind::Other, "User Role deserialization failed")
                                })?;

                            let auth_claim = AuthClaim {
                                roles: match user_roles {
                                    Some(existing_roles) => {
                                        // use id instead of Thing
                                        existing_roles
                                            .get("roles")
                                            .unwrap()
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

                            let token_expiry_duration = Duration::from_secs(15 * 60);
                            let token = sign_jwt(db, &auth_claim, token_expiry_duration, &user)
                                .await
                                .map_err(|_e| {
                                    Error::new(ErrorKind::PermissionDenied, "Unauthorized")
                                })?;

                            ctx.insert_http_header(
                                SET_COOKIE,
                                format!("oauth_client=; HttpOnly; SameSite=Strict"),
                            );

                            ctx.append_http_header("New-Access-Token", format!("Bearer {}", token));

                            return Ok(AuthStatus {
                                is_auth: true,
                                sub: user.id.as_ref().map(|t| &t.id).expect("id").to_raw(),
                            });
                        }
                        None => {
                            return Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"));
                        }
                    }
                }
                Err(_err) => {
                    // Refresh token verification failed
                    return Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"));
                }
            }
        }
        None => Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!")),
    }
}

/// A utility function to get a converted JWT secret key
async fn get_converted_jwt_secret_key<T: Clone + AsSurrealClient>(
    db: &T,
) -> Result<HS256Key, Error> {
    // TODO: Might have to switch to having secret keys in .env
    let mut result = db
        .clone()
        .as_client()
        .query("SELECT * FROM type::table($table) WHERE name = 'jwt_key' LIMIT 1")
        .bind(("table", "crypto_key"))
        .await
        .map_err(|e| {
            eprintln!("Failed to fetch key: {}", e);
            Error::new(ErrorKind::Other, "Database query failed")
        })?;
    let response: Option<SymKey> = result.take(0).map_err(|e| {
        eprintln!("Failed to fetch key: {}", e);
        Error::new(ErrorKind::Other, "Database query deserialization failed")
    })?;

    match &response {
        Some(key_container) => Ok(HS256Key::from_bytes(&key_container.key.clone())),
        None => {
            let key = HS256Key::generate();
            let _reslt: Option<SymKey> = db
                .as_client()
                .create("crypto_key")
                .content(SymKey {
                    key: key.clone().to_bytes(),
                    name: "jwt_key".to_string(),
                })
                .await
                .map_err(|_e| Error::new(ErrorKind::Other, "DB Query failed"))?;

            Ok(key)
        }
    }
}

/// A utility function to verify user login credentials(username/email and password)
pub async fn verify_login_credentials<T: Clone + AsSurrealClient>(
    db: &T,
    raw_user_details: &UserLogins,
) -> Result<User, Error> {
    let user_details = raw_user_details.transformed();

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
        .map_err(|_e| Error::new(ErrorKind::Other, "Database query failed"))?;

    // Get the first result from the first query
    let response: Option<User> = result.take(0).map_err(|e| {
        eprintln!("Failed to fetch key: {}", e);
        Error::new(ErrorKind::Other, "Database query deserialization failed")
    })?;

    match response {
        Some(user) => {
            if bcrypt::verify(&user_details.password.unwrap(), &user.password.as_str()).unwrap()
                && user.status == AccountStatus::Active
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
pub async fn sign_jwt<T: Clone + AsSurrealClient>(
    db: &T,
    auth_claim: &AuthClaim,
    duration: Duration,
    user: &User,
) -> Result<String, Error> {
    let converted_key = get_converted_jwt_secret_key(db)
        .await
        .map_err(|_e| Error::new(ErrorKind::Other, "Database query failed"))?;

    let mut token_claims = Claims::with_custom_claims(auth_claim.clone(), duration);
    token_claims.subject = Some(user.id.as_ref().map(|t| &t.id).expect("id").to_raw());

    Ok(converted_key.authenticate(token_claims).unwrap())
}
