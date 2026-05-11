use async_graphql::{ComplexObject, InputObject, SimpleObject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
pub struct ExchangeRatesResponse {
    pub result: String,
    pub documentation: String,
    pub terms_of_use: String,
    pub time_last_update_unix: i64,
    pub time_last_update_utc: String,
    pub time_next_update_unix: i64,
    pub time_next_update_utc: String,
    pub base_code: String,
    pub target_code: String,
    pub conversion_rate: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, InputObject, Default, SurrealValue)]
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

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, SurrealValue)]
#[graphql(complex)]
pub struct Currency {
    #[graphql(skip)]
    pub id: RecordId,
    pub code: String,
    pub numeric: String,
    pub name: String,
    pub symbol: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[ComplexObject]
impl Currency {
    async fn id(&self) -> Option<String> {
        match &self.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }
    }
}
