use axum::http::HeaderValue;
use jwt_simple::prelude::*;
use lib::utils::{
    auth::AuthClaim, cookie_parser::parse_cookies, custom_traits::AsSurrealClient,
    models::AuthStatus,
};
use std::env;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
};

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
    role::{AdminPrivilege, AuthorizationConstraint},
    user::{
        AccountStatus, DecodedGithubOAuthToken, DecodedGoogleOAuthToken, User, UserLogins,
        UserOutput,
    },
};

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
        .set_revocation_url(RevocationUrl::new("http://localhost:3007".to_string()).unwrap()),
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
pub async fn decode_token(token_header: &HeaderValue) -> Result<JWTClaims<AuthClaim>, Error> {
    let token = token_header.to_str().unwrap().strip_prefix("Bearer ");

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

/// A utility function to confirm auth by parsing relevant headers. Useful for authenticating clients. Includes refresh token handling and OAuth
// TODO: Pass an optional generic context parameter to support both REST and GraphQL refresh token handling - to attach new access token to context headers.
pub async fn confirm_authentication<T: Clone + AsSurrealClient>(
    header_map: Option<&HeaderMap>,
    db: &T,
    // role: &String,
) -> Result<AuthStatus, Error> {
    // let header_map = ctx.data_opt::<HeaderMap>();
    // Process request headers as needed
    match header_map {
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
                                        // let db = ctx
                                        //     .data::<Extension<Arc<Surreal<SurrealClient>>>>()
                                        //     .unwrap();

                                        let token_claims = decode_token(token).await;

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
                                                    current_role: claims.custom.roles[0].clone(),
                                                })
                                            }
                                            Err(_err) => handle_refresh_token(&cookies, db).await,
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
                                                    current_role: "".to_string(),
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
                                                    current_role: "".to_string(),
                                                });
                                            }
                                        }
                                    }
                                }
                                None => {
                                    tracing::error!("Missing oauth client id!");
                                    Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"))
                                }
                            }
                        }
                        None => {
                            tracing::error!("Missing cookie headers!");
                            Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"))
                        }
                    }
                }
                None => {
                    tracing::error!("Missing access token!");
                    Err(Error::new(ErrorKind::PermissionDenied, "Not Authorized!"))
                }
            }
        }
        None => {
            tracing::error!("Invalid request headers!");
            Err(Error::new(ErrorKind::Other, "Invalid request!"))
        }
    }
}

/// A utility function to handle refresh tokens
async fn handle_refresh_token<T: Clone + AsSurrealClient>(
    cookies: &HashMap<String, String>,
    db: &T,
) -> Result<AuthStatus, Error> {
    let converted_jwt_secret_key = get_converted_jwt_secret_key().await?;
    match cookies.get("t") {
        Some(refresh_token) => {
            let refresh_claims =
                converted_jwt_secret_key.verify_token::<AuthClaim>(&refresh_token, None);

            match refresh_claims {
                Ok(refresh_claims) => {
                    let user: Option<User> = db
                        .as_client()
                        .select(("user", refresh_claims.subject.unwrap().as_str()))
                        .await
                        .map_err(|_e| {
                            tracing::error!("User deserialization failed");
                            Error::new(ErrorKind::Other, "User deserialization failed")
                        })?;

                    match user {
                        Some(user) => {
                            let auth_claim = AuthClaim {
                                roles: refresh_claims.custom.roles.clone(),
                            };

                            let token_expiry_duration = Duration::from_secs(15 * 60);
                            let _token = sign_jwt(&auth_claim, token_expiry_duration, &user)
                                .await
                                .map_err(|e| {
                                    tracing::error!("Error: {}", e);
                                    Error::new(ErrorKind::PermissionDenied, "Unauthorized")
                                })?;

                            // TODO: Handle these with the respective functionality for REST and GraphQL contexts(Hint: Might use a Trait for this)
                            // ctx.insert_http_header(
                            //     SET_COOKIE,
                            //     format!("oauth_client=; HttpOnly; SameSite=Strict"),
                            // );

                            // ctx.append_http_header("New-Access-Token", format!("Bearer {}", token));

                            return Ok(AuthStatus {
                                is_auth: true,
                                sub: user.id.as_ref().map(|t| &t.id).expect("id").to_raw(),
                                current_role: refresh_claims.custom.roles[0].clone(),
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
pub async fn sign_jwt(
    auth_claim: &AuthClaim,
    duration: Duration,
    user: &User,
) -> Result<String, Error> {
    let converted_key = get_converted_jwt_secret_key().await?;

    tracing::debug!("Auth Claim: {:?}", auth_claim);

    let mut token_claims = Claims::with_custom_claims(auth_claim.clone(), duration);
    token_claims.subject = Some(user.id.as_ref().map(|t| &t.id).expect("id").to_raw());

    Ok(converted_key.authenticate(token_claims).unwrap())
}

pub async fn get_user_email<T: Clone + AsSurrealClient>(
    db: &T,
    user_id: &str,
) -> Result<String, Error> {
    let result: Option<UserOutput> =
        db.as_client()
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
    auth_constraint: AuthorizationConstraint,
) -> Result<bool, Error> {
    let mut is_admin_privileged = false;
    let mut is_role_privileged = false;

    match &auth_constraint.privilege {
        Some(privilege) => {
            let formated_query = match privilege {
                AdminPrivilege::Admin => format!(
                    "
                    BEGIN TRANSACTION;
                    LET $user = type::thing('user', $user_id);
                    IF !$user.exists() {{
                        THROW 'Invalid Input';
                    }};
                    LET $existing_roles = (SELECT <-(assigned WHERE in = $user) as admin_roles FROM role WHERE (role_name = $current_role_name AND is_admin = true) OR is_super_admin = true)[0]['admin_roles'];
                    IF $existing_roles IS NOT NONE AND array::len($existing_roles) > 0 {{
                        RETURN $existing_roles.map(|$existing_role: any| record::id($existing_role));
                    }} ELSE {{
                        RETURN [];
                    }};
                    COMMIT TRANSACTION;
                    "
                ),
                AdminPrivilege::SuperAdmin => format!(
                    "
                    BEGIN TRANSACTION;
                    LET $user = type::thing('user', $user_id);
                    IF !$user.exists() {{
                        THROW 'Invalid Input';
                    }};
                    LET $existing_roles = (SELECT <-(assigned WHERE in = $user) AS super_admin_roles FROM role WHERE is_super_admin = true AND role_name = $current_role_name)[0]['super_admin_roles'];
                    IF $existing_roles IS NOT NONE AND array::len($existing_roles) > 0 {{
                        RETURN $existing_roles.map(|$existing_role: any| record::id($existing_role));
                    }} ELSE {{
                        RETURN [];
                    }};
                    COMMIT TRANSACTION;
                    "
                ),
            };

            let mut admin_privilege_check_query = db
                .as_client()
                .query(formated_query.as_str())
                .bind(("user_id", auth_status.sub.clone()))
                .bind(("current_role_name", auth_status.current_role.clone()))
                .await
                .map_err(|e| {
                    tracing::error!("{}", e);
                    Error::new(ErrorKind::Other, "Database query failed")
                })?;

            // Get the first result from the first query
            let response: Vec<String> = admin_privilege_check_query.take(0).map_err(|e| {
                tracing::error!("admin_privilege_check_query: {}", e);
                Error::new(ErrorKind::Other, "Database query deserialization failed")
            })?;

            is_admin_privileged = response.len() > 0;
        }
        None => {}
    };

    if auth_constraint.roles.len() > 0 {
        let mut role_privilege_check_query = db
            .as_client()
            .query(
                "
                BEGIN TRANSACTION;
                LET $user = type::thing('user', $user_id);
                IF !$user.exists() {
                    THROW 'Invalid Input';
                };
                LET $existing_roles = (SELECT <-(assigned WHERE in = $user) AS user_roles FROM role WHERE role_name IN $role_constraints AND $current_role_name IN $role_constraints)[0]['user_roles'];
                IF $existing_roles IS NOT NONE AND array::len($existing_roles) > 0 {{
                    RETURN $existing_roles.map(|$existing_role: any| record::id($existing_role));
                }} ELSE {{
                    RETURN [];
                }};
                COMMIT TRANSACTION;
                "
            )
            .bind(("user_id", auth_status.sub.clone()))
            .bind(("role_constraints", auth_constraint.roles.iter().map(|role| role.to_uppercase()).collect::<Vec<String>>()))
            .bind(("current_role_name", auth_status.current_role.clone()))
            .await
            .map_err(|e| {
                tracing::error!("{}", e);
                Error::new(ErrorKind::Other, "Database query failed")
            })?;

        // Get the first result from the first query
        let response: Vec<String> = role_privilege_check_query.take(0).map_err(|e| {
            tracing::error!("role_privilege_check_query: {}", e);
            Error::new(ErrorKind::Other, "Database query deserialization failed")
        })?;

        is_role_privileged = response.len() > 0;
    };

    Ok((auth_constraint.roles.len() > 0
        && is_role_privileged
        && auth_constraint.privilege.is_some()
        && is_admin_privileged)
        || (auth_constraint.roles.len() > 0
            && is_role_privileged
            && auth_constraint.privilege.is_none())
        || (auth_constraint.roles.len() == 0
            && auth_constraint.privilege.is_some()
            && is_admin_privileged))
}
