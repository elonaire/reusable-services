use axum::http::HeaderValue;
use jwt_simple::prelude::*;
use lib::utils::custom_traits::AuthMetadataContext;
use lib::utils::models::{AdminPrivilege, AuthorizationConstraint, MetadataView};
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
    RedirectUrl, RefreshToken, RevocationErrorResponseType, RevocationUrl, Scope,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::graphql::schemas::role::SystemRole;
use crate::graphql::schemas::user::{
    AccountStatus, GithubUserProfile, OAuthTokenPair, User, UserInput, UserLogins,
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
            "oauth_client={}; HttpOnly; SameSite=Lax; Path=/; Domain=.techietenka.com; Secure",
            oauth_client_name.fmt()
        ),
    );

    let sensitive_cookies_expiry_duration = Duration::from_secs(120); // limit the duration of the sensitive cookies
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "j={}; Max-Age={}; HttpOnly; SameSite=Lax; Path=/; Domain=.techietenka.com; Secure",
            csrf_token.secret(),
            sensitive_cookies_expiry_duration.as_secs()
        ),
    );
    ctx.append_http_header(
        SET_COOKIE,
        format!(
            "k={}; Max-Age={}; HttpOnly; SameSite=Lax; Path=/; Domain=.techietenka.com; Secure",
            pkce_verifier.secret(),
            sensitive_cookies_expiry_duration.as_secs()
        ),
    );

    auth_url.to_string()
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
        return handle_normal_auth(token, &cookies, db, ctx).await;
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
            let refresh_claims =
                converted_jwt_secret_key.verify_token::<AuthClaim>(&refresh_token, None);

            match refresh_claims {
                Ok(refresh_claims) => {
                    let Some(sub) = refresh_claims.subject else {
                        return Err(Error::new(ErrorKind::Other, "Unauthorized!"));
                    };

                    let sub_ref = &sub;
                    let current_roles = refresh_claims.custom.roles;

                    let user: Option<User> = db
                        .as_client()
                        .select(("user", sub_ref))
                        .await
                        .map_err(|_e| {
                            tracing::error!("User deserialization failed");
                            Error::new(ErrorKind::Other, "User deserialization failed")
                        })?;

                    match user {
                        Some(user) => {
                            let auth_claim = AuthClaim {
                                roles: current_roles.to_vec(),
                            };

                            let token_expiry_duration = Duration::from_secs(1 * 60);
                            let token = sign_jwt(
                                &auth_claim,
                                token_expiry_duration,
                                &user.id.key().to_string(),
                            )
                            .await
                            .map_err(|e| {
                                tracing::error!("Error: {}", e);
                                Error::new(ErrorKind::PermissionDenied, "Unauthorized")
                            })?;

                            // Set response headers using the AuthMetadataContext trait - works for REST, gRPC, and GraphQL!
                            ctx.set_response_metadata(
                                "set-cookie",
                                "oauth_client=; HttpOnly; SameSite=Lax; Path=/; Domain=.techietenka.com; Secure",
                            )
                            .await;

                            ctx.append_response_metadata("new-access-token", &token)
                                .await;

                            let current_role_permissions =
                                fetch_current_role_permissions(db, sub_ref, &current_roles[0])
                                    .await?;

                            return Ok(AuthStatus {
                                is_auth: true,
                                sub: user.id.key().to_string(),
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
    let formated_query =  match &auth_constraint.privilege {
        AdminPrivilege::Admin => format!(
            "
            BEGIN TRANSACTION;
            LET $user = type::thing('user', $user_id);
            IF !$user.exists() {{
          		THROW 'Invalid Input';
           	}};

            LET $matching_roles = (SELECT ->assigned->(role WHERE (role_name = $current_role_name AND (is_admin OR is_super_admin) AND ->granted->(permission WHERE is_admin OR is_super_admin).name CONTAINSALL $permission_constraints)) AS admin_roles FROM ONLY $user)['admin_roles'];
            IF $matching_roles != NONE AND array::len($matching_roles) > 0 {{
          		RETURN $matching_roles.map(|$matching_role: any| record::id($matching_role));
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
            LET $matching_roles = (SELECT ->assigned->(role WHERE role_name = $current_role_name AND is_super_admin AND ->granted->(permission WHERE is_super_admin OR is_admin).name CONTAINSALL $permission_constraints) AS super_admin_roles FROM ONLY $user)['super_admin_roles'];
            IF $matching_roles != NONE AND array::len($matching_roles) > 0 {{
          		RETURN $matching_roles.map(|$matching_role: any| record::id($matching_role));
           	}} ELSE {{
          		RETURN [];
           	}};

            COMMIT TRANSACTION;
            "
        ),
        AdminPrivilege::None => format!(
            "
            BEGIN TRANSACTION;
            LET $user = type::thing('user', $user_id);
            IF !$user.exists() {{
          		THROW 'Invalid Input';
           	}};

            LET $matching_roles = (SELECT ->assigned->(role WHERE role_name = $current_role_name AND ->granted->permission.name CONTAINSALL $permission_constraints) AS user_roles FROM ONLY $user)['user_roles'];
            IF $matching_roles != NONE AND array::len($matching_roles) > 0 {{
          		RETURN $matching_roles.map(|$matching_role: any| record::id($matching_role));
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
    let response: Vec<String> = admin_privilege_check_query.take(0).map_err(|e| {
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
                        // let email = google_user
                        //     .email;

                        // if email.is_none() {
                        //     tracing::error!("No primary email found");
                        //     return Err(Error::new(ErrorKind::Other, "No primary email found"));
                        // }

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
            BEGIN TRANSACTION;
            LET $user = type::thing('user', $user_id);
            IF !$user.exists() {
          		THROW 'User does not exist';
           	};

            LET $roles = (SELECT ->(assigned WHERE is_default=true)->role.* AS roles FROM ONLY user WHERE id = $user LIMIT 1)['roles'];
            RETURN $roles;
            COMMIT TRANSACTION;
            "
        )
        // Apparently SurrealDB formats the query string before executing it. It may result in unexpected behavior.
        .query(
            "
            BEGIN TRANSACTION;
            LET $role = type::thing('role', $role_id);
            LET $user = type::thing('user', $user_id);
            IF !$role.exists() {
          		THROW 'Role does not exist';
           	};
            IF !$user.exists() {
          		THROW 'User does not exist';
           	};

            LET $roles = (SELECT ->assigned->(role WHERE id = $role)[*] AS roles FROM ONLY user WHERE id = $user LIMIT 1)['roles'];
            RETURN $roles;
            COMMIT TRANSACTION;
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
        Some(_) => user_roles_res.take((1, "role_name")).map_err(|e| {
            tracing::error!("Failed to deserialize roles(take(1)): {}", e);
            Error::new(ErrorKind::Other, "Failed to fetch roles")
        })?,
        None => user_roles_res.take((0, "role_name")).map_err(|e| {
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
                "t={}; HttpOnly; SameSite=Lax; Path=/; Domain=.techietenka.com; Secure",
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
            BEGIN TRANSACTION;
            LET $role = (SELECT VALUE id FROM ONLY role WHERE role_name = $role_name LIMIT 1);
            LET $user = type::thing('user', $user_id);
            IF !$role.exists() {
          		THROW 'Role does not exist';
           	};


            LET $permissions = (SELECT ->assigned->(role WHERE id = $role)->granted->permission[*] AS permissions FROM ONLY user WHERE id = $user OR oauth_user_id = $user_id LIMIT 1)['permissions'];
            RETURN $permissions;
            COMMIT TRANSACTION;
            "
        )
        .bind(("user_id", owned_user_id))
        .bind(("role_name", owned_role_name))
        .await
        .map_err(|e| {
            tracing::error!("DB Query failed. Failed to get role permissions: {}", e);
            Error::new(ErrorKind::Other, "Failed to fetch permissions")
        })?;
    let user_role_permissions: Vec<String> = query_response.take((0, "name")).map_err(|e| {
        tracing::error!("Failed to deserialize permissions(take(0)): {}", e);
        Error::new(ErrorKind::Other, "Failed to fetch permissions")
    })?;

    Ok(user_role_permissions)
}
