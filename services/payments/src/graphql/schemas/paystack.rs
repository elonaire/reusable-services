use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeEvent {
    pub event: String,
    pub data: ChargeData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeData {
    pub id: u64,
    pub domain: String,
    pub status: String,
    pub reference: String,
    pub amount: u64,
    pub message: Option<String>,
    #[serde(rename = "gateway_response")]
    pub gateway_response: String,
    #[serde(rename = "paid_at")]
    pub paid_at: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
    pub channel: String,
    pub currency: String,
    #[serde(rename = "ip_address")]
    pub ip_address: String,
    pub metadata: u64,
    pub log: TransactionLog,
    pub fees: Option<u64>,
    pub customer: Customer,
    pub authorization: Authorization,
    pub plan: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionLog {
    #[serde(rename = "time_spent")]
    pub time_spent: u64,
    pub attempts: u64,
    pub authentication: String,
    pub errors: u64,
    pub success: bool,
    pub mobile: bool,
    pub input: Vec<String>,
    pub channel: Option<String>,
    pub history: Vec<LogEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(rename = "type")]
    pub log_type: String,
    pub message: String,
    pub time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Customer {
    pub id: u64,
    #[serde(rename = "first_name")]
    pub first_name: String,
    #[serde(rename = "last_name")]
    pub last_name: String,
    pub email: String,
    #[serde(rename = "customer_code")]
    pub customer_code: String,
    pub phone: Option<String>,
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "risk_action")]
    pub risk_action: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Authorization {
    #[serde(rename = "authorization_code")]
    pub authorization_code: String,
    pub bin: String,
    pub last4: String,
    #[serde(rename = "exp_month")]
    pub exp_month: String,
    #[serde(rename = "exp_year")]
    pub exp_year: String,
    #[serde(rename = "card_type")]
    pub card_type: String,
    pub bank: String,
    #[serde(rename = "country_code")]
    pub country_code: String,
    pub brand: String,
    #[serde(rename = "account_name")]
    pub account_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeMetadata {
    #[serde(rename = "order_id")]
    pub order_id: String,
}
