use std::sync::Arc;

use async_graphql::{Context, Error, Object, Result};
use axum::{
    http::{header::COOKIE, HeaderMap},
    Extension,
};
use dotenvy::dotenv;
use hyper::{header::SET_COOKIE, Method};
use jwt_simple::prelude::*;
use lib::utils::{auth::{AuthStatus, SymKey, AuthClaim}, cookie_parser::parse_cookies, custom_error::ExtendedError};
use reqwest::{header::HeaderMap as ReqWestHeaderMap, Client as ReqWestClient};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    auth::oauth::{self, OAuthClientName},
    graphql::schemas::{
        role::SystemRole,
        user::{
            DecodedGithubOAuthToken, DecodedGoogleOAuthToken, SurrealRelationQueryResponse,
            User,
        },
    },
};

// use super::mutation::AuthClaim;

pub struct Query;

#[Object]
impl Query {
    async fn get_users(&self, ctx: &Context<'_>) -> Result<Vec<User>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let response = db
            .select("user")
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(response)
    }

    async fn get_user(&self, ctx: &Context<'_>, id: String) -> Result<User> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().unwrap();

        let user: Option<User> = db
            .select(("user", id.as_str()))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        // let user: Option<User> = response.take(0)?;

        match user {
            Some(user) => Ok(user),
            None => Err(Error::new("User not found")),
        }
    }

    async fn check_auth(&self, ctx: &Context<'_>) -> Result<AuthStatus> {
        dotenv().ok();
        // let jwt_secret =
        //     env::var("JWT_SECRET").expect("Missing the JWT_SECRET environment variable.");
        // let jwt_refresh_secret = env::var("JWT_REFRESH_SECRET")
        //     .expect("Missing the JWT_REFRESH_SECRET environment variable.");
        // Process request headers as needed
        match ctx.data_opt::<HeaderMap>() {
            Some(headers) => {
                // Check if Authorization header is present
                match headers.get("Authorization") {
                    Some(token) => {
                        println!("headers: {:?}", headers);
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
                                        println!("oauth_client: {:?}", oauth_client);
                                        if oauth_client.is_empty() {
                                            let key: Vec<u8>;
                                            let db = ctx
                                                .data::<Extension<Arc<Surreal<Client>>>>()
                                                .unwrap();
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

                                            let token_str =
                                                token.to_str().unwrap().strip_prefix("Bearer ");

                                            // Check if token is present and valid
                                            match token_str {
                                                Some(token_str) => {
                                                    let _claims = converted_key
                                                        .verify_token::<AuthClaim>(
                                                            &token_str, None,
                                                        );

                                                    println!("claims: {:?}", _claims);

                                                    match &_claims {
                                                        Ok(_) => {
                                                            // Token verification successful
                                                            return Ok(AuthStatus {
                                                                is_auth: true,
                                                                sub: _claims
                                                                    .as_ref()
                                                                    .unwrap()
                                                                    .subject
                                                                    .as_ref()
                                                                    .map(|t| t.to_string())
                                                                    .unwrap_or("".to_string()),
                                                            });
                                                        }
                                                        Err(_err) => {
                                                            println!("err: {:?}", _err.to_string());
                                                            // Token verification failed, check if refresh token is present
                                                            match cookies.get("t") {
                                                                Some(refresh_token) => {
                                                                    let refresh_claims = converted_key.verify_token::<AuthClaim>(&refresh_token, None);

                                                                    match refresh_claims {
                                                                        Ok(refresh_claims) => {
                                                                            println!("refresh_claims: {:?}", refresh_claims);
                                                                            // TODO: Refresh token verification successful, issue new access token
                                                                            // call sign_in mutation
                                                                            let user: Option<User> =
                                                                                db.select((
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

                                                                                    let auth_claim = AuthClaim {
                                                                                        roles: match user_roles {
                                                                                            Some(existing_roles) => {
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
                                                                                            None => vec![],
                                                                                        },
                                                                                    };

                                                                                    let mut token_claims = Claims::with_custom_claims(auth_claim.clone(), Duration::from_secs(15 * 60));
                                                                                    token_claims.subject = Some(user.id.as_ref().map(|t| &t.id).expect("id").to_raw());

                                                                                    let token = converted_key
                                                                                        .authenticate(token_claims)
                                                                                        .unwrap();

                                                                                    ctx.insert_http_header(
                                                                                        SET_COOKIE,
                                                                                        format!("oauth_client="),
                                                                                    );

                                                                                    ctx.append_http_header(
                                                                                        "New-Access-Token",
                                                                                        format!("Bearer {}", token),
                                                                                    );

                                                                                    return Ok(AuthStatus {
                                                                                        is_auth: true,
                                                                                        sub: user.id.as_ref().map(|t| &t.id).expect("id").to_raw(),
                                                                                    });
                                                                                }
                                                                                None => {
                                                                                    return Err(ExtendedError::new(
                                                                                        "Not Authorized!",
                                                                                        Some(403.to_string()),
                                                                                    )
                                                                                    .build());
                                                                                }
                                                                            }

                                                                            // return Ok(
                                                                            //     AuthStatus {
                                                                            //         is_auth: false,
                                                                            //     },
                                                                            // );
                                                                        }
                                                                        Err(_err) => {
                                                                            // Refresh token verification failed
                                                                            return Err(ExtendedError::new(
                                                                                        "Not Authorized!",
                                                                                        Some(403.to_string())
                                                                                    ).build());
                                                                        }
                                                                    }
                                                                }
                                                                None => Err(ExtendedError::new(
                                                                    "Not Authorized!",
                                                                    Some(403.to_string()),
                                                                )
                                                                .build()),
                                                            }
                                                            // return Err(Error::new("Not Authorized!"));
                                                        }
                                                    }
                                                }
                                                None => Err(ExtendedError::new(
                                                    "Invalid request!",
                                                    Some(400.to_string()),
                                                )
                                                .build()),
                                            }
                                        } else {
                                            let oauth_client_name =
                                                oauth::OAuthClientName::from_str(oauth_client);

                                            match oauth_client_name {
                                                OAuthClientName::Google => {
                                                    // make a request to google oauth server to verify the token
                                                    let response =
                                                        reqwest::get(format!("https://oauth2.googleapis.com/tokeninfo?access_token={}", token.to_str().unwrap().strip_prefix("Bearer ").unwrap()).as_str())
                                                            .await?
                                                            .json::<DecodedGoogleOAuthToken>()
                                                            .await?;
                                                    println!("response: {:?}", response);

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
                                                        "application/vnd.github+json"
                                                            .parse()
                                                            .unwrap(),
                                                    );

                                                    req_headers.append(
                                                        "X-GitHub-Api-Version",
                                                        "2022-11-28".parse().unwrap(),
                                                    );

                                                    println!("req_headers: {:?}", req_headers);

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

                                                    println!("response: {:?}", response);

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
                    None => {
                        Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build())
                    }
                }
            }
            None => Err(ExtendedError::new("Invalid request!", Some(400.to_string())).build()),
        }
    }
}
