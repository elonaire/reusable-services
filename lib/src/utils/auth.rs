use async_graphql::SimpleObject;
use serde::{Deserialize, Serialize};

use super::models::AuthStatus;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymKey {
    pub name: String,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct AuthClaim {
    // pub sub: String,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct DecodeTokenResponse {
    #[serde(rename = "decodeToken")]
    pub decode_token: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, SimpleObject)]
pub struct CheckAuthResponse {
    #[serde(rename = "checkAuth")]
    pub check_auth: AuthStatus,
}
