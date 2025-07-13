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

use crate::graphql::schemas::role::SystemRole;
use crate::graphql::schemas::user::{GoogleUserInfo, OAuthUser, SurrealRelationQueryResponse};
use crate::graphql::schemas::{
    role::{AdminPrivilege, AuthorizationConstraint},
    user::{AccountStatus, GithubUserProfile, User, UserLogins, UserOutput},
};
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
                    "https://www.googleapis.com/auth/userinfo.email".to_string(),
                ))
                .add_scope(Scope::new(
                    "https://www.googleapis.com/auth/userinfo.profile".to_string(),
                ))
        }
        OAuthClientName::Github => {
            oauth_client
                .authorize_url(CsrfToken::new_random)
                // Set the desired scopes.
                .add_scope(Scope::new("read:user".to_string()))
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
            "oauth_client={}; HttpOnly; SameSite=Lax; Path=/; Secure",
            oauth_client_name.fmt()
        ),
    );

    let sensitive_cookies_expiry_duration = Duration::from_secs(120); // limit the duration of the sensitive cookies
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "j={}; Max-Age={}; HttpOnly; SameSite=Lax; Path=/; Secure",
            csrf_token.secret(),
            sensitive_cookies_expiry_duration.as_secs()
        ),
    );
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "k={}; Max-Age={}; HttpOnly; SameSite=Lax; Path=/; Secure",
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
                                        match cookies.get("oauth_user_roles_jwt") {
                                            Some(oauth_user_roles_jwt) => {
                                                let token_claims = decode_token(
                                                    &HeaderValue::from_str(oauth_user_roles_jwt)
                                                        .unwrap(),
                                                )
                                                .await;

                                                match &token_claims {
                                                    Ok(claims) => {
                                                        // Token verification successful
                                                        let oauth_client_name =
                                                            OAuthClientName::from_str(oauth_client);

                                                        match oauth_client_name {
                                                            OAuthClientName::Google => {
                                                                let google_user =
                                                                    verify_oauth_token::<
                                                                        GoogleUserInfo,
                                                                    >(
                                                                        OAuthClientName::Google,
                                                                        token,
                                                                    )
                                                                    .await?;

                                                                return Ok(AuthStatus {
                                                                    is_auth: true,
                                                                    sub: google_user.resource_name,
                                                                    current_role: claims
                                                                        .custom
                                                                        .roles[0]
                                                                        .clone(),
                                                                });
                                                            }
                                                            OAuthClientName::Github => {
                                                                let github_user =
                                                                    verify_oauth_token::<
                                                                        GithubUserProfile,
                                                                    >(
                                                                        OAuthClientName::Github,
                                                                        token,
                                                                    )
                                                                    .await?;

                                                                return Ok(AuthStatus {
                                                                    is_auth: true,
                                                                    sub: github_user.id.to_string(),
                                                                    current_role: claims
                                                                        .custom
                                                                        .roles[0]
                                                                        .clone(),
                                                                });
                                                            }
                                                        }
                                                        // Ok(AuthStatus {
                                                        //     is_auth: true,
                                                        //     sub: claims
                                                        //         .subject
                                                        //         .as_ref()
                                                        //         .map(|t| t.to_string())
                                                        //         .unwrap_or("".to_string()),
                                                        //     current_role: claims.custom.roles[0].clone(),
                                                        // })
                                                    }
                                                    Err(_err) => {
                                                        tracing::error!("Failed to decode jwt!");
                                                        Err(Error::new(
                                                            ErrorKind::PermissionDenied,
                                                            "Not Authorized!",
                                                        ))
                                                    }
                                                }
                                            }
                                            None => {
                                                tracing::error!(
                                                    "Missing oauth user permissions jwt!"
                                                );
                                                Err(Error::new(
                                                    ErrorKind::PermissionDenied,
                                                    "Not Authorized!",
                                                ))
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
                            let _token = sign_jwt(
                                &auth_claim,
                                token_expiry_duration,
                                &user.id.as_ref().map(|t| &t.id).expect("id").to_raw(),
                            )
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
    user_id: &str,
) -> Result<String, Error> {
    let converted_key = get_converted_jwt_secret_key().await?;

    tracing::debug!("Auth Claim: {:?}", auth_claim);

    let mut token_claims = Claims::with_custom_claims(auth_claim.clone(), duration);
    token_claims.subject = Some(user_id.to_string());

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

/// A generic utility function to verify OAuth tokens
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
                        "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses",
                    )
                    .headers(req_headers)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::debug!("OAuth request to Google failed: {:?}", e);
                        Error::new(ErrorKind::Other, "OAuth request to Google failed")
                    })?;

            // Log the raw JSON response
            // let response_text = response
            //     .text()
            //     .await
            //     .map_err(|e| {
            //         tracing::debug!("Failed to read response body: {:?}", e);
            //         Error::new(ErrorKind::Other, "Failed to read response body")
            //     })?;
            // tracing::debug!("Raw response body: {}", response_text);

            let user_data = response.json::<T>().await.map_err(|e| {
                tracing::debug!("Google Token deserialization failed: {:?}", e);
                Error::new(ErrorKind::Other, "Google Token deserialization failed")
            })?;

            tracing::debug!("user_data: {:?}", user_data);

            Ok(user_data)
        }
        OAuthClientName::Github => {
            // make a request to github oauth server to verify the token
            let client = ReqWestClient::new();

            let mut req_headers = ReqWestHeaderMap::new();
            req_headers.insert("Authorization", token.to_owned());

            req_headers.append("Accept", "application/vnd.github+json".parse().unwrap());

            req_headers.append("X-GitHub-Api-Version", "2022-11-28".parse().unwrap());

            let user_agent = env::var("GITHUB_OAUTH_USER_AGENT")
                .expect("Missing the GITHUB_OAUTH_USER_AGENT environment variable.");

            req_headers.append("User-Agent", user_agent.as_str().parse().unwrap());

            let response = client
                .request(Method::GET, "https://api.github.com/user")
                .headers(req_headers)
                .send()
                .await
                .map_err(|e| {
                    tracing::debug!("OAuth request to GitHub failed: {:?}", e);
                    Error::new(ErrorKind::Other, "OAuth request to GitHub failed")
                })?;

            // let response_text =
            //     response.text().await.map_err(|e| {
            //         tracing::debug!(
            //             "Failed to read response body: {:?}",
            //             e
            //         );
            //         Error::new(
            //             ErrorKind::Other,
            //             "Failed to read response body",
            //         )
            //     })?;
            // tracing::debug!(
            //     "Rate limit response: {}",
            //     response_text
            // );

            let user_data = response.json::<T>().await.map_err(|e| {
                tracing::error!("GitHub Token deserialization failed: {}", e);
                Error::new(ErrorKind::Other, "GitHub Token deserialization failed")
            })?;

            tracing::debug!("user_data: {:?}", user_data);

            Ok(user_data)
        }
    }
}

pub async fn create_oauth_user_if_not_exists<T: Clone + AsSurrealClient>(
    db: &T,
    oauth_client_name: OAuthClientName,
    user: &OAuthUser,
) -> Result<(), Error> {
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
                    .bind(("oauth_user_id", google_user.resource_name.clone()))
                    .await
                    .map_err(|e| {
                        tracing::error!("DB Query Error: {}", e);
                        Error::new(ErrorKind::Other, "Internal Server error")
                    })?;

                let existing_user: Option<UserOutput> = db_query.take(0).map_err(|e| {
                    tracing::error!("Deserialization Error: {}", e);
                    Error::new(ErrorKind::Other, "Internal Server error")
                })?;

                match existing_user {
                    Some(_existing_user) => Ok(()),
                    None => {
                        let user = User {
                            email: google_user
                                .email_addresses
                                .iter()
                                .find(|email| email.metadata.primary)
                                .unwrap()
                                .value
                                .clone(),
                            oauth_client: Some(OAuthClientName::Google),
                            oauth_user_id: Some(google_user.resource_name.clone()),
                            status: AccountStatus::Active,
                            ..User::default()
                        };

                        let _created_user = create_user(db, user).await?;

                        Ok(())
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

                let existing_user: Option<UserOutput> = db_query.take(0).map_err(|e| {
                    tracing::error!("Deserialization Error: {}", e);
                    Error::new(ErrorKind::Other, "Internal Server error")
                })?;

                match existing_user {
                    Some(_existing_user) => Ok(()),
                    None => {
                        tracing::debug!("Getting None");
                        let user = User {
                            email: github_user.email.as_ref().unwrap().to_owned(),
                            oauth_client: Some(OAuthClientName::Github),
                            oauth_user_id: Some(github_user.id.to_string()),
                            status: AccountStatus::Active,
                            ..User::default()
                        };

                        let _created_user = create_user(db, user).await?;

                        Ok(())
                    }
                }
            } else {
                // Handle mismatch
                tracing::error!("Invalid Github OAuth user!");
                Err(Error::new(ErrorKind::Other, "Invalid Google OAuth user!"))
            }
        }
    }
}

pub async fn fetch_default_user_roles<T: Clone + AsSurrealClient>(
    db: &T,
    user_id: &str,
) -> Result<Vec<String>, Error> {
    let owned_user_id = user_id.to_string();

    let mut user_roles_res = db
        .as_client()
        .query(
            "
            SELECT ->(assigned WHERE is_default=true)->role.* AS roles FROM ONLY user WHERE id = type::thing('user', $user_id) OR oauth_user_id = $user_id LIMIT 1
        ",
        )
        .bind(("user_id", owned_user_id))
        .await
        .map_err(|_e| Error::new(ErrorKind::Other, "DB Query failed: Get Roles"))?;
    let user_roles: Option<SurrealRelationQueryResponse<SystemRole>> =
        user_roles_res.take(0).map_err(|e| {
            tracing::error!("Failed to get roles: {}", e);
            Error::new(ErrorKind::Other, "Failed to get roles")
        })?;

    match user_roles {
        Some(roles) => Ok(roles
            .get("roles")
            .unwrap()
            .into_iter()
            .map(|role| {
                let name_str = format!("{}", role.role_name);
                tracing::debug!("name_str: {}", name_str);
                name_str
            })
            .collect()),
        None => {
            tracing::error!("Cannot get authenticated without roles");
            Err(Error::new(ErrorKind::PermissionDenied, "Forbidden"))
        }
    }
}
