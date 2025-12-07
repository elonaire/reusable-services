use std::collections::HashMap;

use async_graphql::{InputObject, SimpleObject};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct ExchangeRatesResponse {
    pub success: bool,
    pub timestamp: u64,
    pub base: String,
    pub date: String,
    pub rates: HashMap<String, f64>
}
