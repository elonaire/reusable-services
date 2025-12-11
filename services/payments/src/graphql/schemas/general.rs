use std::collections::HashMap;

use async_graphql::{ComplexObject, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct ExchangeRatesResponse {
    pub success: bool,
    pub timestamp: u64,
    pub base: String,
    pub date: String,
    pub rates: HashMap<String, f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, InputObject, Default)]
pub struct FetchCurrenciesQueryFilters {
    pub currency_id: Option<String>,
    pub code: Option<String>,
    pub numeric: Option<String>,
    pub search_term: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, InputObject, Default)]
pub struct CurrencyInput {
    pub code: String,
    pub numeric: String,
    pub name: String,
    pub symbol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct Currency {
    #[graphql(skip)]
    pub id: RecordId,
    pub code: String,
    pub numeric: String,
    pub name: String,
    pub symbol: String,
    pub created_at: String,
    pub updated_at: String,
}

#[ComplexObject]
impl Currency {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }
}
