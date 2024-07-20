use async_graphql::SimpleObject;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct AuthStatus {
    pub is_auth: bool,
    pub sub: String,
}

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
